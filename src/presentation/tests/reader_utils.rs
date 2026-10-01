use super::*;
use crate::definitions::device_response::{DocumentErrorCode, Status};
use crate::definitions::session::SessionTranscript180135;
use crate::definitions::x509::test::TestPki;
use crate::definitions::x509::validation::{
    AnyDocType, ExtensionRule, IssuerProfile, MdocProfile, RdnRule, ReaderProfile,
};
use crate::issuance::mdoc::test::{
    expired, issue_test_mdoc, issue_test_mdoc_with_namespaces, valid_for_a_year, MDL_DOC_TYPE,
};
use crate::presentation::test_utils::{
    self, eudi_pid_profile, Ask, TestExchange, EUDI_PID_DS_EKU, EUDI_PID_READER_EKU,
    PHOTO_ID_DOC_TYPE, PID_DOC_TYPE,
};

use crate::presentation::test_utils::ISOMDL_NAMESPACE;
fn wanted(doc_types: &[&str]) -> BTreeSet<String> {
    doc_types.iter().map(|d| d.to_string()).collect()
}

fn ask<'a>(doc_type: &'a str, elements: &'a [&'a str]) -> Ask<'a> {
    (doc_type, ISOMDL_NAMESPACE, elements)
}

/// Run the reader's validation over `response`, asking for `doc_types`.
async fn validate(
    exchange: &TestExchange,
    response: &DeviceResponse,
    trust_anchors: &TrustAnchorRegistry,
    doc_types: &[&str],
    pki: &TestPki,
) -> ResponseValidationOutcome {
    let requested = wanted(doc_types);
    let config = ReaderValidationConfig {
        trust_anchors,
        requested_doc_types: Some(&requested),
        options: &ValidationOptions::default(),
        profiles: &AnyDocType(MdocProfile::MDL),
    };
    validate_response(
        response,
        &exchange.session_transcript(),
        &config,
        &pki.fetcher(),
        &exchange.e_reader_key_private(),
    )
    .await
}

/// Same as [`validate`], but under a caller-supplied certificate profile.
async fn validate_with_profile(
    exchange: &TestExchange,
    response: &DeviceResponse,
    trust_anchors: &TrustAnchorRegistry,
    doc_types: &[&str],
    pki: &TestPki,
    profile: MdocProfile,
) -> ResponseValidationOutcome {
    let requested = wanted(doc_types);
    let config = ReaderValidationConfig {
        trust_anchors,
        requested_doc_types: Some(&requested),
        options: &ValidationOptions::default(),
        profiles: &AnyDocType(profile),
    };
    validate_response(
        response,
        &exchange.session_transcript(),
        &config,
        &pki.fetcher(),
        &exchange.e_reader_key_private(),
    )
    .await
}

/// The point of the whole exercise: a credential whose document signer carries a
/// non-mDL EKU validates under its own profile, and *only* under its own profile.
///
/// The second half is what makes this a real test — if the EKU were not actually
/// checked, the first assertion would pass for the wrong reason.
#[tokio::test]
async fn a_document_signer_with_a_non_mdl_eku_validates_under_its_own_profile() {
    let pki = test_utils::pid_pki();
    let mdoc = issue_test_mdoc(&pki, PID_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let response = exchange.respond(&[ask(PID_DOC_TYPE, &["age_over_21"])]);

    let outcome = validate_with_profile(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[PID_DOC_TYPE],
        &pki,
        eudi_pid_profile(),
    )
    .await;

    assert_eq!(outcome.documents[0].doc_type, PID_DOC_TYPE);
    assert!(outcome.failed.is_empty());

    // And the mDL profile rejects the very same credential, on the EKU.
    let outcome = validate_with_profile(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[PID_DOC_TYPE],
        &pki,
        MdocProfile::MDL,
    )
    .await;

    assert!(outcome.documents.is_empty());
    assert!(
        has(&outcome.failed[0].errors, "certificate_chain"),
        "the mDL profile accepted a non-mDL document signer EKU: {:?}",
        outcome.failed[0].errors
    );
}

/// A profile document written before `crl_distribution_points` and `issuer_alternative_name`
/// existed must still load, and must take the ISO/IEC 18013-5 Annex B rule rather than the
/// laxer one — a missing field should never quietly relax a check.
#[test]
fn a_profile_without_the_extension_rules_still_loads_as_annex_b() {
    let issuer: IssuerProfile = serde_json::from_value(serde_json::json!({
        "document_signer_eku": "1.0.18013.5.1.2",
        "state_or_province": "match_if_present",
    }))
    .unwrap();
    assert_eq!(issuer, MdocProfile::MDL.issuer);

    let reader: ReaderProfile = serde_json::from_value(serde_json::json!({
        "reader_auth_eku": "1.0.18013.5.1.6",
    }))
    .unwrap();
    assert_eq!(reader, MdocProfile::MDL.reader);
}

/// Profiles are configuration, so they have to survive being persisted alongside it.
#[test]
fn a_profile_round_trips_through_json() {
    // Every field is off its default, so a dropped or transposed one shows up.
    let profile = MdocProfile {
        issuer: IssuerProfile {
            document_signer_eku: EUDI_PID_DS_EKU,
            state_or_province: RdnRule::Required,
            crl_distribution_points: ExtensionRule::Optional,
            issuer_alternative_name: ExtensionRule::Optional,
        },
        reader: ReaderProfile {
            reader_auth_eku: EUDI_PID_READER_EKU,
            crl_distribution_points: ExtensionRule::Optional,
            issuer_alternative_name: ExtensionRule::Optional,
        },
    };

    let json = serde_json::to_value(profile).unwrap();
    // The OIDs travel as dotted strings, which is how a profile document quotes them.
    assert_eq!(json["issuer"]["document_signer_eku"], "1.3.130.2.0.0.1.2");
    assert_eq!(json["issuer"]["state_or_province"], "required");
    assert_eq!(json["issuer"]["crl_distribution_points"], "optional");
    assert_eq!(json["reader"]["issuer_alternative_name"], "optional");

    let restored: MdocProfile = serde_json::from_value(json).unwrap();
    assert_eq!(restored, profile);
}

/// The one validated document, failing loudly with the reasons if there isn't one.
fn only_valid(outcome: &ResponseValidationOutcome) -> &ValidatedDocument {
    outcome.single_document().unwrap_or_else(|| {
        panic!(
            "expected exactly one validated document; failed={:?} errors={:?}",
            outcome.failed, outcome.errors
        )
    })
}

/// The one failed document, failing loudly if there isn't exactly one.
fn only_failed(outcome: &ResponseValidationOutcome) -> &FailedDocument {
    match outcome.failed.as_slice() {
        [document] => document,
        other => panic!("expected exactly one failed document, got {other:?}"),
    }
}

fn has(errors: &[DocumentError], code: &str) -> bool {
    errors.iter().any(|e| e.code() == code)
}

/// The whole point of the change: a credential that is not an mDL validates.
///
/// The mDL hardcode failed this with `DocumentTypeError` before any cryptography ran:
/// why a downstream consumer forked the parsing helpers rather than fix them here.
#[tokio::test]
async fn a_non_mdl_document_validates() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, PHOTO_ID_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let response = exchange.respond(&[ask(PHOTO_ID_DOC_TYPE, &["family_name"])]);

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[PHOTO_ID_DOC_TYPE],
        &pki,
    )
    .await;

    assert_eq!(only_valid(&outcome).doc_type, PHOTO_ID_DOC_TYPE);
}

/// Two credentials of different doc types are each reported in full.
///
/// A single flat `response` map plus a `doc_types` list would collapse this:
/// collected from *all* documents — so the elements of one credential were reported
/// under the authentication result of another.
#[tokio::test]
async fn two_doc_types_are_reported_separately() {
    let pki = TestPki::issuer();
    let mdl = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
    let passport = issue_test_mdoc(&pki, PHOTO_ID_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdl, passport]);
    let response = exchange.respond(&[
        ask(MDL_DOC_TYPE, &["age_over_21"]),
        ask(PHOTO_ID_DOC_TYPE, &["family_name"]),
    ]);

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE, PHOTO_ID_DOC_TYPE],
        &pki,
    )
    .await;

    assert_eq!(outcome.documents.len(), 2);
    assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);

    let by_type: BTreeMap<_, _> = outcome
        .documents
        .iter()
        .map(|d| (d.doc_type.as_str(), d))
        .collect();
    assert_eq!(
        by_type[MDL_DOC_TYPE].namespaces[ISOMDL_NAMESPACE]["age_over_21"],
        serde_json::json!(true)
    );
    assert_eq!(
        by_type[PHOTO_ID_DOC_TYPE].namespaces[ISOMDL_NAMESPACE]["family_name"],
        serde_json::json!("Smith")
    );
}

/// Two documents of the *same* doc type are both evaluated.
///
/// `DeviceResponse.documents` is an array in the published 18013-5, and nothing
/// forbids duplicates. The old reader used `.find()` and silently dropped the second.
#[tokio::test]
async fn two_documents_of_the_same_doc_type_are_both_evaluated() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let mut response = exchange.respond(&[ask(MDL_DOC_TYPE, &["age_over_21"])]);
    TestExchange::duplicate_document(&mut response, 0);

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE],
        &pki,
    )
    .await;

    assert_eq!(outcome.documents.len(), 2);
    // Two valid documents is not "one valid document".
    assert!(outcome.single_document().is_none());
}

/// One bad credential must not take the others down with it.
#[tokio::test]
async fn one_invalid_document_does_not_taint_the_others() {
    let pki = TestPki::issuer();
    let mdl = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
    let passport = issue_test_mdoc(&pki, PHOTO_ID_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdl, passport]);
    let mut response = exchange.respond(&[
        ask(MDL_DOC_TYPE, &["age_over_21"]),
        ask(PHOTO_ID_DOC_TYPE, &["family_name"]),
    ]);

    // Break exactly one document's proof of possession.
    let index = response
        .documents
        .as_ref()
        .unwrap()
        .iter()
        .position(|d| d.doc_type == PHOTO_ID_DOC_TYPE)
        .unwrap();
    test_utils::tamper_device_signature(TestExchange::document_mut(&mut response, index));

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE, PHOTO_ID_DOC_TYPE],
        &pki,
    )
    .await;

    let good = only_valid(&outcome);
    assert_eq!(good.doc_type, MDL_DOC_TYPE);
    assert_eq!(
        good.namespaces[ISOMDL_NAMESPACE]["age_over_21"],
        serde_json::json!(true)
    );

    let bad = only_failed(&outcome);
    assert_eq!(bad.claimed_doc_type, PHOTO_ID_DOC_TYPE);
    assert!(
        has(&bad.errors, "device_authentication"),
        "{:?}",
        bad.errors
    );
    // Only the device signature failed; the issuer's chain was fine, and the
    // disclosed data is still available to show the user.
    assert!(!bad.namespaces.is_empty());
}

/// The holder's label and the issuer's signature must agree on the doc type.
///
/// Nothing in this crate checked this before: a holder could relabel a credential
/// and the reader would report the relabelled type.
#[tokio::test]
async fn a_relabelled_document_is_caught() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let mut response = exchange.respond(&[ask(MDL_DOC_TYPE, &["age_over_21"])]);
    test_utils::set_document_doc_type(
        TestExchange::document_mut(&mut response, 0),
        PHOTO_ID_DOC_TYPE,
    );

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[PHOTO_ID_DOC_TYPE],
        &pki,
    )
    .await;

    let document = only_failed(&outcome);
    assert!(
        has(&document.errors, "doc_type_mismatch"),
        "{:?}",
        document.errors
    );
    // Only the holder's label is reported: the mismatch means neither is trustworthy
    // as an identifier, and the authenticated one is not exposed on a failure.
    assert_eq!(document.claimed_doc_type, PHOTO_ID_DOC_TYPE);
    assert!(outcome.documents.is_empty());
}

/// An empty registry is a deployment error, and says nothing about the device.
///
/// Device authentication is *not attempted*, so there must be no
/// `device_authentication` error claiming the device failed a check that never ran.
#[tokio::test]
async fn an_empty_registry_reports_misconfiguration_not_a_device_failure() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let response = exchange.respond(&[ask(MDL_DOC_TYPE, &["age_over_21"])]);

    let outcome = validate(
        &exchange,
        &response,
        &TrustAnchorRegistry::default(),
        &[MDL_DOC_TYPE],
        &pki,
    )
    .await;

    let document = only_failed(&outcome);
    assert!(has(&document.errors, "no_trust_anchors_configured"));
    assert!(has(&document.errors, "device_authentication_not_attempted"));
    assert!(
        !has(&document.errors, "device_authentication"),
        "reported a device authentication failure for a check that never ran: {:?}",
        document.errors
    );
    // And it is not confused with an untrusted credential.
    assert!(!has(&document.errors, "certificate_chain"));
}

/// An expired credential is invalid, full stop.
///
/// Recording the expiry in `errors` while leaving
/// `issuer_authentication: Valid` next to it, so a consumer reading the status
/// accepted an expired mDL.
#[tokio::test]
async fn an_expired_credential_is_invalid() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, expired()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let response = exchange.respond(&[ask(MDL_DOC_TYPE, &["age_over_21"])]);

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE],
        &pki,
    )
    .await;

    let document = only_failed(&outcome);
    assert!(
        has(&document.errors, "mso_expired"),
        "{:?}",
        document.errors
    );
    assert!(outcome.documents.is_empty());
}

/// An element that cannot be represented is named, its siblings survive, and the document
/// still validates.
///
/// The float is signed by the issuer rather than tampered in afterwards, so its digest
/// matches: the element is authentic and this library simply has no JSON for a CBOR float.
/// Tampering would break the digest and prove only that a tampered document fails.
/// Rejecting the whole credential over a projection limitation would be wrong, and dropping
/// the element silently — as the old code did — would make a partial disclosure
/// indistinguishable from a complete one.
#[tokio::test]
async fn an_undecodable_element_is_named_and_its_siblings_survive() {
    let pki = TestPki::issuer();
    let namespaces = [(
        ISOMDL_NAMESPACE.to_string(),
        [
            ("age_over_21".to_string(), ciborium::Value::Float(1.5)),
            (
                "family_name".to_string(),
                ciborium::Value::Text("Smith".to_string()),
            ),
        ]
        .into_iter()
        .collect(),
    )]
    .into_iter()
    .collect();
    let mdoc = issue_test_mdoc_with_namespaces(&pki, MDL_DOC_TYPE, valid_for_a_year(), namespaces)
        .unwrap();

    let exchange = TestExchange::new([mdoc]);
    let response = exchange.respond(&[ask(MDL_DOC_TYPE, &["age_over_21", "family_name"])]);

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE],
        &pki,
    )
    .await;

    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    let document = only_valid(&outcome);
    assert!(
        document.warnings.iter().any(|w| matches!(
            w,
            DocumentWarning::UndecodableElement { element_identifier, .. }
                if element_identifier == "age_over_21"
        )),
        "{:?}",
        document.warnings
    );
    assert_eq!(
        document.namespaces[ISOMDL_NAMESPACE]["family_name"],
        serde_json::json!("Smith")
    );
    assert!(!document.namespaces[ISOMDL_NAMESPACE].contains_key("age_over_21"));
}

/// A document with no certificate chain fails on its own.
#[tokio::test]
async fn a_missing_x5chain_is_isolated_to_its_document() {
    let pki = TestPki::issuer();
    let mdl = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
    let passport = issue_test_mdoc(&pki, PHOTO_ID_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdl, passport]);
    let mut response = exchange.respond(&[
        ask(MDL_DOC_TYPE, &["age_over_21"]),
        ask(PHOTO_ID_DOC_TYPE, &["family_name"]),
    ]);
    let index = response
        .documents
        .as_ref()
        .unwrap()
        .iter()
        .position(|d| d.doc_type == PHOTO_ID_DOC_TYPE)
        .unwrap();
    test_utils::strip_x5chain(TestExchange::document_mut(&mut response, index));

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE, PHOTO_ID_DOC_TYPE],
        &pki,
    )
    .await;

    let stripped = only_failed(&outcome);
    assert_eq!(stripped.claimed_doc_type, PHOTO_ID_DOC_TYPE);
    assert!(
        has(&stripped.errors, "missing_x5chain"),
        "{:?}",
        stripped.errors
    );

    assert_eq!(only_valid(&outcome).doc_type, MDL_DOC_TYPE);
}

/// An unsolicited credential is never touched, and the requested one still validates.
#[tokio::test]
async fn an_unrequested_document_is_rejected_without_being_validated() {
    let pki = TestPki::issuer();
    let mdl = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
    let passport = issue_test_mdoc(&pki, PHOTO_ID_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdl, passport]);
    let response = exchange.respond(&[
        ask(MDL_DOC_TYPE, &["age_over_21"]),
        ask(PHOTO_ID_DOC_TYPE, &["family_name"]),
    ]);

    // The reader only ever asked for an mDL.
    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE],
        &pki,
    )
    .await;

    assert_eq!(only_valid(&outcome).doc_type, MDL_DOC_TYPE);
    assert_eq!(
        outcome.rejected,
        vec![RejectedDocument {
            claimed_doc_type: PHOTO_ID_DOC_TYPE.to_string()
        }]
    );
}

/// Getting only credentials nobody asked for is a failure, not an empty success.
#[tokio::test]
async fn a_response_of_only_unrequested_documents_is_not_evaluated() {
    let pki = TestPki::issuer();
    let passport = issue_test_mdoc(&pki, PHOTO_ID_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([passport]);
    let response = exchange.respond(&[ask(PHOTO_ID_DOC_TYPE, &["family_name"])]);

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE],
        &pki,
    )
    .await;

    assert_eq!(outcome.errors, [ResponseError::AllDocumentsRejected]);
    // `documents: None` never travels without a reason. The type cannot enforce that
    // pairing since the fields are independent, so it is pinned here and on every
    // other path that can produce `None`.
    assert!(outcome.documents.is_empty());
    assert_eq!(outcome.rejected.len(), 1);
}

/// A response carrying no documents at all.
#[tokio::test]
async fn a_response_with_no_documents_is_not_evaluated() {
    let response = DeviceResponse {
        version: DeviceResponse::VERSION.to_string(),
        documents: None,
        document_errors: None,
        status: Status::GeneralError,
    };
    let anchors = TrustAnchorRegistry::default();
    let requested = wanted(&[MDL_DOC_TYPE]);
    let config = ReaderValidationConfig {
        trust_anchors: &anchors,
        requested_doc_types: Some(&requested),
        options: &ValidationOptions::default(),
        profiles: &AnyDocType(MdocProfile::MDL),
    };
    let (transcript, reader_key) = test_utils::test_session_transcript();

    let outcome = validate_response::<SessionTranscript180135, (), _>(
        &response,
        &transcript,
        &config,
        &(),
        &reader_key,
    )
    .await;

    assert_eq!(outcome.errors, [ResponseError::NoDocuments]);
    assert!(outcome.documents.is_empty());
    assert!(outcome.failed.is_empty());
}

/// Not telling the reader what was requested disables the filter, and says so.
#[tokio::test]
async fn an_unknown_request_skips_the_filter_with_a_warning() {
    let pki = TestPki::issuer();
    let passport = issue_test_mdoc(&pki, PHOTO_ID_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([passport]);
    let response = exchange.respond(&[ask(PHOTO_ID_DOC_TYPE, &["family_name"])]);

    let anchors = pki.iaca_registry();
    let config = ReaderValidationConfig {
        trust_anchors: &anchors,
        requested_doc_types: None,
        options: &ValidationOptions::default(),
        profiles: &AnyDocType(MdocProfile::MDL),
    };
    let outcome = validate_response(
        &response,
        &exchange.session_transcript(),
        &config,
        &pki.fetcher(),
        &exchange.e_reader_key_private(),
    )
    .await;

    assert_eq!(outcome.documents.len(), 1);
    assert_eq!(
        outcome.warnings,
        [ResponseWarning::RequestedDocTypesUnknown]
    );
}
/// A populated registry that does not contain *this* issuer is a different
/// diagnosis from an empty registry, and must not be reported as one.
///
/// `validate_document` splits these deliberately: `NoTrustAnchorsConfigured` means
/// the deployment is misconfigured, `CertificateChain` means the credential is
/// untrusted. Before this change both produced the same string.
#[tokio::test]
async fn an_untrusted_issuer_is_not_confused_with_a_missing_registry() {
    let pki = TestPki::issuer();
    let stranger = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let response = exchange.respond(&[ask(MDL_DOC_TYPE, &["age_over_21"])]);

    // A registry with a root in it — just not the one that issued this credential.
    let outcome = validate(
        &exchange,
        &response,
        &stranger.iaca_registry(),
        &[MDL_DOC_TYPE],
        &pki,
    )
    .await;

    let document = only_failed(&outcome);
    assert!(
        has(&document.errors, "certificate_chain"),
        "{:?}",
        document.errors
    );
    assert!(
        !has(&document.errors, "no_trust_anchors_configured"),
        "an untrusted issuer was reported as a missing registry: {:?}",
        document.errors
    );
    assert!(has(&document.errors, "device_authentication_not_attempted"));
}

/// A revoked certificate is an error. A CRL the reader could not *reach* is a warning.
///
/// The two are easy to transpose, and transposing them fails open.
#[tokio::test]
async fn a_revoked_certificate_is_an_error_not_a_warning() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let response = exchange.respond(&[ask(MDL_DOC_TYPE, &["age_over_21"])]);

    let requested = wanted(&[MDL_DOC_TYPE]);
    let anchors = pki.iaca_registry();
    let config = ReaderValidationConfig {
        trust_anchors: &anchors,
        requested_doc_types: Some(&requested),
        options: &ValidationOptions::default(),
        profiles: &AnyDocType(MdocProfile::MDL),
    };
    let outcome = validate_response(
        &response,
        &exchange.session_transcript(),
        &config,
        // The same PKI, now publishing a CRL that names its own signing certificate.
        &pki.fetcher_revoking(&[pki.leaf_serial()]),
        &exchange.e_reader_key_private(),
    )
    .await;

    let document = only_failed(&outcome);
    assert!(
        has(&document.errors, "certificate_chain"),
        "{:?}",
        document.errors
    );
    assert!(
        document.warnings.is_empty(),
        "revocation was demoted to a warning: {:?}",
        document.warnings
    );
    assert_eq!(outcome.documents.len(), 0);
}

/// A subset response is a legitimate answer, and the holder's `status` is not a verdict.
///
/// A holder that returns one of two requested credentials, and sets a non-OK status
/// while doing it, has still returned a valid credential. `status` is holder-controlled
/// and outside every signature, so treating it as a verdict would let the party being
/// verified invalidate its own good response.
#[tokio::test]
async fn a_subset_response_with_a_holder_status_is_still_evaluated() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let mut response = exchange.respond(&[ask(MDL_DOC_TYPE, &["age_over_21"])]);
    response.status = Status::GeneralError;
    response.document_errors = Some(NonEmptyVec::new(BTreeMap::from([(
        PHOTO_ID_DOC_TYPE.to_string(),
        DocumentErrorCode::DataNotReturned,
    )])));

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE, PHOTO_ID_DOC_TYPE],
        &pki,
    )
    .await;

    assert_eq!(outcome.documents.len(), 1);
    assert!(outcome.failed.is_empty());
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);

    // Both reach the caller: without them a reader cannot tell "the holder declined
    // the passport" from "the holder said nothing about it".
    assert_eq!(outcome.status, Some(Status::GeneralError));
    assert_eq!(
        outcome.document_errors,
        vec![BTreeMap::from([(
            PHOTO_ID_DOC_TYPE.to_string(),
            DocumentErrorCode::DataNotReturned,
        )])]
    );
}

/// `errors.is_empty()` is the whole verdict, so a failed document must show up there.
///
/// Failure detail lives on the document itself; this is only about the one check a
/// consumer makes. Without it a response whose only document failed device
/// authentication reports no errors at all, and every other field a consumer used to
/// read was renamed or deleted — so this is the one that would fail open silently.
#[tokio::test]
async fn a_failed_document_is_visible_in_the_response_errors() {
    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();

    let exchange = TestExchange::new([mdoc]);
    let mut response = exchange.respond(&[ask(MDL_DOC_TYPE, &["age_over_21"])]);
    test_utils::tamper_device_signature(TestExchange::document_mut(&mut response, 0));

    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE],
        &pki,
    )
    .await;

    assert!(outcome.documents.is_empty());
    assert_eq!(outcome.failed.len(), 1);
    assert!(
        outcome.errors.contains(&ResponseError::DocumentsFailed),
        "{:?}",
        outcome.errors
    );
}

/// The outcome must survive JSON, because consumers persist it.
///
/// The types layer internally-tagged enums over `NonEmptyVec`'s `try_from`/`into`
/// serde attributes and over `Status`'s integer representation, which is exactly the
/// combination that quietly stops round-tripping. `VerifiedMso` in particular copies
/// its timestamps out of `ValidityInfo` because that type serializes as tagged CBOR.
#[tokio::test]
async fn an_outcome_survives_a_json_round_trip() {
    let pki = TestPki::issuer();
    let mdl = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
    let passport = issue_test_mdoc(&pki, PHOTO_ID_DOC_TYPE, expired()).unwrap();

    let exchange = TestExchange::new([mdl, passport]);
    let response = exchange.respond(&[
        ask(MDL_DOC_TYPE, &["age_over_21"]),
        ask(PHOTO_ID_DOC_TYPE, &["family_name"]),
    ]);

    // One valid document, one invalid, so both shapes are exercised.
    let outcome = validate(
        &exchange,
        &response,
        &pki.iaca_registry(),
        &[MDL_DOC_TYPE, PHOTO_ID_DOC_TYPE],
        &pki,
    )
    .await;
    assert_eq!(outcome.documents.len(), 1);

    let json = serde_json::to_string(&outcome).expect("outcome does not serialize");
    let back: ResponseValidationOutcome =
        serde_json::from_str(&json).expect("outcome does not deserialize");
    assert_eq!(outcome, back);

    // The failed variant too — it holds a different set of fields.
    let empty = DeviceResponse {
        version: DeviceResponse::VERSION.to_string(),
        documents: None,
        document_errors: None,
        status: Status::GeneralError,
    };
    let anchors = TrustAnchorRegistry::default();
    let requested = wanted(&[MDL_DOC_TYPE]);
    let config = ReaderValidationConfig {
        trust_anchors: &anchors,
        requested_doc_types: Some(&requested),
        options: &ValidationOptions::default(),
        profiles: &AnyDocType(MdocProfile::MDL),
    };
    let failed = validate_response::<SessionTranscript180135, (), _>(
        &empty,
        &exchange.session_transcript(),
        &config,
        &(),
        &[0u8; 32],
    )
    .await;
    let json = serde_json::to_string(&failed).expect("failed outcome does not serialize");
    let back: ResponseValidationOutcome =
        serde_json::from_str(&json).expect("failed outcome does not deserialize");
    assert_eq!(failed, back);
}
