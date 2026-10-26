use std::collections::BTreeSet;

use crate::definitions::{
    x509::{
        revocation::RevocationFetcher,
        test::TestPki,
        trust_anchor::TrustAnchorRegistry,
        validation::{AnyDocType, MdocProfile, ValidationOptions},
    },
    DeviceResponse,
};
use crate::issuance::mdoc::test::{issue_test_mdoc, valid_for_a_year, MDL_DOC_TYPE};
use crate::presentation::authentication::{DocumentError, ResponseValidationOutcome};
use crate::presentation::reader_utils::{validate_response, ReaderValidationConfig};
use crate::presentation::test_utils::TestExchange;

use crate::presentation::test_utils::ISOMDL_NAMESPACE;

fn requested(doc_types: &[&str]) -> BTreeSet<String> {
    doc_types.iter().map(|d| d.to_string()).collect()
}

/// Validate `response` the way a reader would, with everything spelled out.
async fn validate(
    exchange: &TestExchange,
    response: &DeviceResponse,
    trust_anchors: &TrustAnchorRegistry,
    revocation_fetcher: &impl RevocationFetcher,
) -> ResponseValidationOutcome {
    let wanted = requested(&[MDL_DOC_TYPE]);
    let config = ReaderValidationConfig {
        trust_anchors,
        requested_doc_types: Some(&wanted),
        options: &ValidationOptions::default(),
        profiles: &AnyDocType(MdocProfile::MDL),
    };
    validate_response(
        response,
        &exchange.session_transcript(),
        &config,
        revocation_fetcher,
        &exchange.e_reader_key_private(),
    )
    .await
}

/// The trusted-exchange assertion for COSE_Mac0 device authentication.
///
/// MAC0 is not a variation on the Sign1 path: EMacKey comes from
/// `ECDH(SDeviceKey, EReaderKey)` (ISO 18013-5 §9.1.3.5), so this is the only test that
/// exercises the reader's ephemeral private key and the static device key taken from
/// the verified MSO. The Sign1 equivalent is
/// [`end_to_end::an_mdl_presents_end_to_end`], which runs the whole public flow.
#[tokio::test]
async fn fully_trusted_mac0_exchange_reports_no_errors() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new_mac0([mdoc]);
    let response = exchange.respond(&[(MDL_DOC_TYPE, ISOMDL_NAMESPACE, &["age_over_21"])]);

    let outcome = validate(&exchange, &response, &pki.iaca_registry(), &pki.fetcher()).await;

    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
    let document = outcome
        .single_document()
        .expect("the credential should have validated");
    assert_eq!(document.doc_type, MDL_DOC_TYPE);
    assert_eq!(
        document.namespaces[ISOMDL_NAMESPACE]["age_over_21"],
        serde_json::json!(true)
    );
}

/// A MAC0 response verified with the wrong reader key must not authenticate.
///
/// Without this, `fully_trusted_mac0_exchange_reports_no_errors` would still pass if
/// EMacKey derivation ignored the reader key entirely on both sides.
#[tokio::test]
async fn mac0_device_authentication_fails_with_the_wrong_reader_key() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new_mac0([mdoc]);
    let response = exchange.respond(&[(MDL_DOC_TYPE, ISOMDL_NAMESPACE, &["age_over_21"])]);

    let mut wrong_key = exchange.e_reader_key_private();
    wrong_key[0] ^= 0xff;
    let registry = pki.iaca_registry();
    let wanted = requested(&[MDL_DOC_TYPE]);
    let config = ReaderValidationConfig {
        trust_anchors: &registry,
        requested_doc_types: Some(&wanted),
        options: &ValidationOptions::default(),
        profiles: &AnyDocType(MdocProfile::MDL),
    };
    let outcome = validate_response(
        &response,
        &exchange.session_transcript(),
        &config,
        &pki.fetcher(),
        &wrong_key,
    )
    .await;

    // Only the device's proof of possession fails, and it fails on its own.
    let document = &outcome.failed[0];
    assert!(
        document
            .errors
            .iter()
            .any(|e| matches!(e, DocumentError::DeviceAuthentication { .. })),
        "{:?}",
        document.errors
    );
}

/// Device authentication must never be attempted when issuer authentication has not
/// succeeded.
///
/// The device key is carried *inside* the MSO. Verifying a DeviceAuth signature
/// against a key taken from an unverified MSO proves only that whoever wrote the
/// response holds the key they themselves put there — so a reader that reported the
/// device as authenticated here would be telling the consumer the holder proved
/// possession when nothing of the sort was established.
///
/// The DeviceAuth signature in this response is genuine and would verify; the point
/// is that it is never checked, because there is no trusted MSO to check it against.
#[tokio::test]
async fn device_authentication_is_not_attempted_without_issuer_authentication() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let response = exchange.respond(&[(MDL_DOC_TYPE, ISOMDL_NAMESPACE, &["age_over_21"])]);

    // The one thing changed from the happy path: nothing trusts this issuer.
    let outcome = validate(
        &exchange,
        &response,
        &TrustAnchorRegistry::default(),
        &pki.fetcher(),
    )
    .await;

    let document = &outcome.failed[0];
    assert!(
        document
            .errors
            .contains(&DocumentError::NoTrustAnchorsConfigured),
        "{:?}",
        document.errors
    );
    assert!(
        document
            .errors
            .iter()
            .any(|e| matches!(e, DocumentError::DeviceAuthenticationNotAttempted { .. })),
        "{:?}",
        document.errors
    );
    // The claim itself is still reported, so a consumer can show it as unverified.
    assert_eq!(
        document.namespaces[ISOMDL_NAMESPACE]["age_over_21"],
        serde_json::json!(true)
    );
}

/// The full public flow, end to end, over a PKI the reader trusts.
///
/// Everything else in this file drives [`TestExchange`], which builds a
/// [`DeviceResponse`] directly and skips engagement, session encryption and the device
/// state machine. The integration tests in `tests/` do run the public flow, but with an
/// empty trust anchor registry, so they cannot assert that anything validated. These
/// are the only tests that do both.
mod end_to_end {
    use std::collections::BTreeMap;

    use p256::ecdsa::signature::Signer;
    use uuid::Uuid;

    use crate::cbor;
    use crate::definitions::device_engagement::{CentralClientMode, DeviceRetrievalMethods};
    use crate::definitions::session::Handover;
    use crate::definitions::x509::revocation::RevocationFetcher;
    use crate::definitions::x509::test::TestPki;
    use crate::definitions::x509::trust_anchor::TrustAnchorRegistry;
    use crate::definitions::x509::validation::{AnyDocType, MdocProfile, ProfileSelector};
    use crate::definitions::{BleOptions, DeviceRetrievalMethod, SessionEstablishment};
    use crate::issuance::mdoc::test::{
        issue_test_mdoc, issue_test_mdoc_with_namespaces, valid_for_a_year, MDL_DOC_TYPE,
    };
    use crate::issuance::Mdoc;
    use crate::presentation::authentication::{
        DocumentError, DocumentWarning, ResponseValidationOutcome, ValidatedDocument,
    };
    use crate::presentation::device::{Document, Documents, SessionManagerInit};
    use crate::presentation::reader;
    use crate::presentation::test_utils::{
        self, eudi_pid_profile, pid_namespaces, pid_pki, Ask, TestExchange, PHOTO_ID_DOC_TYPE,
        PID_DOC_TYPE, PID_MANDATORY_ATTRIBUTES,
    };

    use super::ISOMDL_NAMESPACE;

    /// Drive `mdocs` through engagement, session establishment, request, response and
    /// validation, disclosing exactly `asks`.
    async fn present(
        mdocs: impl IntoIterator<Item = Mdoc>,
        trust_anchors: TrustAnchorRegistry,
        fetcher: &impl RevocationFetcher,
        asks: &[Ask<'_>],
        profiles: &impl ProfileSelector,
    ) -> ResponseValidationOutcome {
        let documents: Documents = mdocs
            .into_iter()
            .map(|mdoc| (mdoc.doc_type.clone(), Document::from(mdoc)))
            .collect::<BTreeMap<_, _>>()
            .try_into()
            .expect("a presentation needs at least one mdoc");

        let retrieval = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
            peripheral_server_mode: None,
            central_client_mode: Some(CentralClientMode {
                uuid: Uuid::new_v4(),
            }),
        }));
        let engaged = SessionManagerInit::initialise(documents, Some(retrieval), None)
            .expect("failed to initialise the device")
            .engage(Handover::QR)
            .expect("failed to engage");
        let qr = engaged.qr_handover().expect("failed to render the QR");

        let (items_requests, permitted) = test_utils::build_request(asks);
        let (mut reader_session, request, _ble_ident) = reader::SessionManager::establish_session(
            reader::Handover::QR(qr),
            items_requests
                .try_into()
                .expect("a presentation needs at least one ask"),
            trust_anchors,
        )
        .expect("failed to establish the reader session");

        let establishment: SessionEstablishment =
            cbor::from_slice(&request).expect("the reader sent undecodable bytes");
        // The reader sends no `readerAuth`, and the device registers no reader roots,
        // so its absence is a warning rather than an error.
        let (mut device_session, validated_request) = engaged
            .process_session_establishment(
                establishment,
                TrustAnchorRegistry::default(),
                profiles,
                &(),
            )
            .await
            .expect("the device could not process session establishment");
        assert!(!validated_request.has_errors(), "{validated_request:?}");

        device_session.prepare_response(&validated_request.requested_items(), permitted);

        // One signature per document, so this must be a loop: a single-document test
        // would pass with the body run once.
        let key = TestExchange::device_signing_key();
        let mut signed = 0;
        while let Some((_, payload)) = device_session.get_next_signature_payload() {
            let signature: p256::ecdsa::Signature = key.sign(payload);
            device_session
                .submit_next_signature(signature.to_vec())
                .expect("failed to submit the signature");
            signed += 1;
        }
        assert_eq!(
            signed,
            asks.len(),
            "one signature per document was expected"
        );

        let response = device_session
            .retrieve_response()
            .expect("the device produced no response");

        reader_session
            .handle_response(&response, profiles, fetcher)
            .await
    }

    /// Nothing anywhere in the outcome went wrong, and the one document is `doc_type`.
    fn sole_valid_document<'a>(
        outcome: &'a ResponseValidationOutcome,
        doc_type: &str,
    ) -> &'a ValidatedDocument {
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        assert!(outcome.rejected.is_empty(), "{:?}", outcome.rejected);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);

        let document = outcome
            .single_document()
            .expect("the credential should have validated");
        assert!(document.warnings.is_empty(), "{:?}", document.warnings);
        assert_eq!(document.doc_type, doc_type);
        document
    }

    /// A consumer's own [`CertificateProfile`], run end to end through the reader API.
    ///
    /// The credential is signed by an ETSI-shaped PKI carrying no mdoc key purpose, and is
    /// validated under [`EuAgeVerificationProfile`] — a profile that borrows no rule from any
    /// shipped [`MdocProfile`]. `MdocProfile` appears only as the pair holding the two
    /// halves, and on the reader half, which this test does not vary.
    ///
    /// No hand-written [`ProfileSelector`]: [`AnyDocType`] is generic over both halves, so
    /// a custom profile goes through the same convenience the built-ins do. That is the
    /// property under test — the x509-level test already covers the profile's own rules.
    ///
    /// [`CertificateProfile`]: crate::definitions::x509::validation::CertificateProfile
    /// [`EuAgeVerificationProfile`]: crate::definitions::x509::validation::EuAgeVerificationProfile
    #[tokio::test]
    async fn a_custom_profile_validates_through_the_reader_api() {
        use crate::definitions::x509::validation::EuAgeVerificationProfile;
        use crate::definitions::x509::validation::EU_AGE_VERIFICATION_DOC_TYPE as AV_DOC_TYPE;

        let pki = TestPki::etsi_av();
        let profiles = AnyDocType(MdocProfile {
            issuer: EuAgeVerificationProfile,
            reader: MdocProfile::MDL.reader,
        });

        let outcome = present(
            [issue_test_mdoc(&pki, AV_DOC_TYPE, valid_for_a_year()).unwrap()],
            pki.iaca_registry(),
            &pki.fetcher(),
            &[(AV_DOC_TYPE, ISOMDL_NAMESPACE, &["age_over_21"])],
            &profiles,
        )
        .await;

        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        let document = outcome
            .single_document()
            .expect("the credential should have validated");
        assert_eq!(document.doc_type, AV_DOC_TYPE);
        assert_eq!(
            document.namespaces[ISOMDL_NAMESPACE]["age_over_21"],
            serde_json::json!(true)
        );

        // Age verification revokes through the Trusted List, so the profile declares
        // `RevocationRule::OutOfBand` and no CRL is fetched. The caller still has to be
        // told, or it reads a clean outcome as "not revoked" — so declaring it out of band
        // records a warning rather than nothing.
        assert!(
            matches!(
                document.warnings.as_slice(),
                [DocumentWarning::Revocation { detail }]
                    if detail.contains("revocation is published out of band")
            ),
            "{:?}",
            document.warnings
        );

        // The same credential under a shipped mdoc profile fails: supporting age
        // verification did not loosen those.
        let outcome = present(
            [issue_test_mdoc(&pki, AV_DOC_TYPE, valid_for_a_year()).unwrap()],
            pki.iaca_registry(),
            &pki.fetcher(),
            &[(AV_DOC_TYPE, ISOMDL_NAMESPACE, &["age_over_21"])],
            &AnyDocType(MdocProfile::MDL),
        )
        .await;
        let failed = outcome
            .failed
            .first()
            .expect("an ETSI signer should fail the mDL profile");
        assert!(
            failed
                .errors
                .iter()
                .any(|e| matches!(e, DocumentError::CertificateChain { .. })),
            "{:?}",
            failed.errors
        );
    }

    #[tokio::test]
    async fn an_mdl_presents_end_to_end() {
        let pki = TestPki::issuer();
        let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

        let outcome = present(
            [mdoc],
            pki.iaca_registry(),
            &pki.fetcher(),
            &[(MDL_DOC_TYPE, ISOMDL_NAMESPACE, &["age_over_21"])],
            &AnyDocType(MdocProfile::MDL),
        )
        .await;

        let document = sole_valid_document(&outcome, MDL_DOC_TYPE);
        assert_eq!(
            document.namespaces[ISOMDL_NAMESPACE]["age_over_21"],
            serde_json::json!(true)
        );
    }

    /// Two credentials in one exchange, each validated and reported on its own.
    ///
    /// The device signs each document separately, and the reader reports each with its
    /// own authenticated doc type — so a single flat response, or a single
    /// authentication verdict earned by whichever document came first, would fail here.
    ///
    /// Both share a certificate profile because only one applies to a whole response.
    /// An mDL presented alongside an EUDI PID is not yet supported for that reason.
    #[tokio::test]
    async fn two_credentials_present_end_to_end() {
        let pki = TestPki::issuer();
        let mdl = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
        let passport = issue_test_mdoc(&pki, PHOTO_ID_DOC_TYPE, valid_for_a_year()).unwrap();

        let outcome = present(
            [mdl, passport],
            pki.iaca_registry(),
            &pki.fetcher(),
            &[
                (MDL_DOC_TYPE, ISOMDL_NAMESPACE, &["age_over_21"]),
                (PHOTO_ID_DOC_TYPE, ISOMDL_NAMESPACE, &["family_name"]),
            ],
            &AnyDocType(MdocProfile::MDL),
        )
        .await;

        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        assert!(outcome.rejected.is_empty(), "{:?}", outcome.rejected);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(outcome.documents.len(), 2, "{outcome:?}");

        let mdl = outcome
            .document(MDL_DOC_TYPE)
            .expect("the mDL should have validated");
        assert_eq!(
            mdl.namespaces[ISOMDL_NAMESPACE]["age_over_21"],
            serde_json::json!(true)
        );

        let passport = outcome
            .document(PHOTO_ID_DOC_TYPE)
            .expect("the passport should have validated");
        assert!(
            !passport.namespaces[ISOMDL_NAMESPACE].contains_key("age_over_21"),
            "each document must carry only its own elements: {:?}",
            passport.namespaces
        );
    }

    /// An mDL and an EUDI PID in one response, each under its own certificate profile.
    ///
    /// The two are issued by different PKIs with different document signer EKUs, so a
    /// single profile applied to the whole response cannot validate both — this is what
    /// selecting per doc type is for. Swap the selector for either profile alone and one
    /// of the two credentials fails on its EKU.
    ///
    /// CRLs are skipped: each PKI signs its own, and the static test fetcher serves one.
    /// That costs a revocation warning per document, so warnings are not asserted here.
    #[tokio::test]
    async fn an_mdl_and_a_pid_present_together() {
        let mdl_pki = TestPki::issuer();
        let pid_pki = pid_pki();
        let mdl = issue_test_mdoc(&mdl_pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
        let pid = issue_test_mdoc_with_namespaces(
            &pid_pki,
            PID_DOC_TYPE,
            valid_for_a_year(),
            pid_namespaces(),
        )
        .unwrap();

        let mut anchors = mdl_pki.iaca_registry();
        anchors.anchors.extend(pid_pki.iaca_registry().anchors);

        let profiles: BTreeMap<String, MdocProfile> = [
            (MDL_DOC_TYPE.to_string(), MdocProfile::MDL),
            (PID_DOC_TYPE.to_string(), eudi_pid_profile()),
        ]
        .into_iter()
        .collect();

        let outcome = present(
            [mdl, pid],
            anchors,
            &(),
            &[
                (MDL_DOC_TYPE, ISOMDL_NAMESPACE, &["age_over_21"]),
                (PID_DOC_TYPE, PID_DOC_TYPE, &["family_name"]),
            ],
            &profiles,
        )
        .await;

        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        assert_eq!(outcome.documents.len(), 2, "{outcome:?}");

        assert_eq!(
            outcome
                .document(MDL_DOC_TYPE)
                .expect("the mDL should have validated")
                .namespaces[ISOMDL_NAMESPACE]["age_over_21"],
            serde_json::json!(true)
        );
        assert_eq!(
            outcome
                .document(PID_DOC_TYPE)
                .expect("the PID should have validated")
                .namespaces[PID_DOC_TYPE]["family_name"],
            serde_json::json!("Garcia")
        );
    }

    /// A doc type the selector does not cover is refused without any cryptography.
    #[tokio::test]
    async fn a_document_without_a_profile_is_refused() {
        let pki = TestPki::issuer();
        let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
        let profiles: BTreeMap<String, MdocProfile> = BTreeMap::new();

        let outcome = present(
            [mdoc],
            pki.iaca_registry(),
            &pki.fetcher(),
            &[(MDL_DOC_TYPE, ISOMDL_NAMESPACE, &["age_over_21"])],
            &profiles,
        )
        .await;

        assert!(outcome.documents.is_empty(), "{:?}", outcome.documents);
        let failed = &outcome.failed[0];
        assert!(
            failed.errors.contains(&DocumentError::NoProfileConfigured {
                doc_type: MDL_DOC_TYPE.to_string()
            }),
            "{:?}",
            failed.errors
        );
        // The claim is still reported, so a consumer can show it as unverified.
        assert_eq!(
            failed.namespaces[ISOMDL_NAMESPACE]["age_over_21"],
            serde_json::json!(true)
        );
    }

    /// The same flow for a credential that shares nothing with the mDL but the 18013-5
    /// envelope: its own doc type, namespace, attributes and document signer EKU.
    #[tokio::test]
    async fn an_eudi_pid_presents_end_to_end() {
        let pki = pid_pki();
        let mdoc = issue_test_mdoc_with_namespaces(
            &pki,
            PID_DOC_TYPE,
            valid_for_a_year(),
            pid_namespaces(),
        )
        .unwrap();

        let requested: Vec<&str> = PID_MANDATORY_ATTRIBUTES.iter().map(|(k, _)| *k).collect();
        let outcome = present(
            [mdoc],
            pki.iaca_registry(),
            &pki.fetcher(),
            &[(PID_DOC_TYPE, PID_DOC_TYPE, &requested)],
            &AnyDocType(eudi_pid_profile()),
        )
        .await;

        let document = sole_valid_document(&outcome, PID_DOC_TYPE);
        for (name, value) in PID_MANDATORY_ATTRIBUTES {
            assert_eq!(
                document.namespaces[PID_DOC_TYPE][name],
                serde_json::json!(value),
                "{name} did not survive the round trip"
            );
        }
    }
}
