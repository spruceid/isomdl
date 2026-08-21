use crate::definitions::helpers::ByteStr;

use super::*;
use crate::definitions::mso::DigestId;
use serde_json::json;

#[test]
fn filter_permitted() {
    let requested = serde_json::from_value(json!([
        {
            "docType": "doc_type_1",
            "nameSpaces": {
                "namespace_1": {
                    "element_1": false,
                    "element_2": false,
                },
                "namespace_2": {
                    "element_1": false,
                }
            }
        },
        {
            "docType": "doc_type_2",
            "nameSpaces": {
                "namespace_1": {
                    "element_1": false,
                }
            }
        }
    ]))
    .unwrap();
    let permitted = serde_json::from_value(json!({
        "doc_type_1": {
            "namespace_1": [
                "element_1",
                "element_3"
            ],
            "namespace_3": [
                "element_1",
            ]
        },
        "doc_type_3": {
            "namespace_1": [
                "element_1",
            ],
        }
    }))
    .unwrap();
    let expected: PermittedItems = serde_json::from_value(json!({
        "doc_type_1": {
            "namespace_1": [
                "element_1",
            ],
        }
    }))
    .unwrap();

    let filtered = super::filter_permitted(&requested, permitted);

    assert_eq!(expected, filtered);
}

#[test]
fn test_parse_age_from_element_identifier() {
    let element_identifier = "age_over_88".to_string();
    let age = parse_age_from_element_identifier(element_identifier).unwrap();
    assert_eq!(age, 88)
}

#[test]
fn test_age_attestation_response() {
    let requested_element_identifier = "age_over_23".to_string();
    let element_identifier1 = "age_over_18".to_string();
    let element_identifier2 = "age_over_22".to_string();
    let element_identifier3 = "age_over_21".to_string();

    let random = vec![1, 2, 3, 4, 5];
    let issuer_signed_item1 = IssuerSignedItem {
        digest_id: DigestId::new(1),
        random: ByteStr::from(random.clone()),
        element_identifier: element_identifier1.clone(),
        element_value: ciborium::Value::Bool(true),
    };

    let issuer_signed_item2 = IssuerSignedItem {
        digest_id: DigestId::new(2),
        random: ByteStr::from(random.clone()),
        element_identifier: element_identifier2.clone(),
        element_value: ciborium::Value::Bool(false),
    };

    let issuer_signed_item3 = IssuerSignedItem {
        digest_id: DigestId::new(3),
        random: ByteStr::from(random),
        element_identifier: element_identifier3.clone(),
        element_value: ciborium::Value::Bool(false),
    };

    let issuer_item1 = Tag24::new(issuer_signed_item1).unwrap();
    let issuer_item2 = Tag24::new(issuer_signed_item2).unwrap();
    let issuer_item3 = Tag24::new(issuer_signed_item3).unwrap();
    let mut issuer_items = NonEmptyMap::new(element_identifier1, issuer_item1);
    issuer_items.insert(element_identifier2, issuer_item2.clone());
    issuer_items.insert(element_identifier3, issuer_item3);

    let result = nearest_age_attestation(requested_element_identifier, issuer_items)
        .expect("failed to process age attestation request");

    assert_eq!(result.unwrap().inner_bytes, issuer_item2.inner_bytes);
}

#[test]
fn test_str_to_u8() {
    let wib = "8";
    let x = wib.as_bytes();

    println!("{x:?}");
}
mod request_processing {
    use super::super::*;
    use crate::definitions::x509::test::TestPki;
    use crate::definitions::x509::validation::{AnyDocType, MdocProfile, ReaderProfile};
    use crate::issuance::mdoc::test::{issue_test_mdoc, valid_for_a_year, MDL_DOC_TYPE};
    use crate::presentation::test_utils::{
        test_namespaces, unauthenticated_request, TestReader, PHOTO_ID_DOC_TYPE,
    };

    /// An engaged device holding one mDL, and a reader that has agreed keys with it.
    fn engage() -> (SessionManagerEngaged, TestReader, TestPki) {
        let pki = TestPki::issuer();
        let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
        let documents = NonEmptyMap::new(mdoc.doc_type.clone(), Document::from(mdoc));

        let engaged = SessionManagerInit::initialise(documents, None, None)
            .unwrap()
            .engage(Handover::QR)
            .unwrap();
        let reader = TestReader::engage(&engaged);
        (engaged, reader, pki)
    }

    /// Send `request` to the device and return what it made of it.
    async fn process(
        engaged: SessionManagerEngaged,
        reader: &mut TestReader,
        request: &DeviceRequest,
        trusted_verifiers: TrustAnchorRegistry,
    ) -> (SessionManager, RequestAuthenticationOutcome) {
        process_with_profiles(
            engaged,
            reader,
            request,
            trusted_verifiers,
            &AnyDocType(MdocProfile::MDL),
        )
        .await
    }

    /// As [`process`], under a caller-supplied certificate profile.
    async fn process_with_profiles(
        engaged: SessionManagerEngaged,
        reader: &mut TestReader,
        request: &DeviceRequest,
        trusted_verifiers: TrustAnchorRegistry,
        profiles: &impl ProfileSelector,
    ) -> (SessionManager, RequestAuthenticationOutcome) {
        let establishment = reader.session_establishment(request);
        engaged
            .process_session_establishment(establishment, trusted_verifiers, profiles, &())
            .await
            .unwrap()
    }

    /// Every doc request is evaluated, not just the first: `reader_auth` is a field of
    /// `DocRequest`, so stopping at `.first()` let the rest ride on one signature.
    #[tokio::test]
    async fn every_doc_request_is_reported() {
        let (engaged, mut reader, _) = engage();
        let request = unauthenticated_request(&[MDL_DOC_TYPE, PHOTO_ID_DOC_TYPE]);

        let (_, outcome) = process(
            engaged,
            &mut reader,
            &request,
            TrustAnchorRegistry::default(),
        )
        .await;

        assert_eq!(outcome.doc_requests.len(), 2);
        assert_eq!(outcome.doc_requests[0].items_request.doc_type, MDL_DOC_TYPE);
        assert_eq!(
            outcome.doc_requests[1].items_request.doc_type,
            PHOTO_ID_DOC_TYPE
        );
        // The compatibility shim returns them all, in order.
        assert_eq!(
            outcome
                .requested_items()
                .iter()
                .map(|i| i.doc_type.clone())
                .collect::<Vec<_>>(),
            vec![MDL_DOC_TYPE.to_string(), PHOTO_ID_DOC_TYPE.to_string()]
        );
    }

    /// With no trust anchors the holder cannot check reader auth, so its absence is a
    /// warning rather than an error — otherwise every legal unauthenticated request,
    /// including the ones this library's own reader sends, would look broken.
    #[tokio::test]
    async fn a_missing_reader_auth_is_a_warning_not_an_error() {
        let (engaged, mut reader, _) = engage();
        let request = unauthenticated_request(&[MDL_DOC_TYPE]);

        let (_, outcome) = process(
            engaged,
            &mut reader,
            &request,
            TrustAnchorRegistry::default(),
        )
        .await;

        let doc_request = &outcome.doc_requests[0];
        assert!(!outcome.has_errors(), "{:?}", outcome);
        assert!(!doc_request.reader_auth_present);
        assert!(doc_request.warnings.contains_key("reader_authentication"));
        // But it is still not an authenticated reader, and the holder can tell.
        assert!(!doc_request.is_reader_authenticated());
        assert!(outcome.authenticated_requested_items().is_empty());
    }

    /// Configuring reader trust anchors *is* the holder saying it requires reader auth,
    /// so an unsigned request is a failure rather than a warning. This is what lets a
    /// holder decide on `has_errors()` alone.
    #[tokio::test]
    async fn a_missing_reader_auth_is_an_error_when_anchors_are_configured() {
        let (engaged, mut reader, _) = engage();
        let request = unauthenticated_request(&[MDL_DOC_TYPE]);

        let (_, outcome) = process(
            engaged,
            &mut reader,
            &request,
            TestPki::reader().registry(x509::trust_anchor::TrustPurpose::ReaderCa),
        )
        .await;

        let doc_request = &outcome.doc_requests[0];
        assert!(outcome.has_errors());
        assert!(doc_request
            .errors
            .contains_key("reader_authentication_errors"));
        assert!(
            doc_request.warnings.is_empty(),
            "{:?}",
            doc_request.warnings
        );
        assert!(!doc_request.is_reader_authenticated());
    }

    /// A reader whose certificate chains to a trusted root and whose signature
    /// verifies is authenticated.
    #[tokio::test]
    async fn a_trusted_reader_is_authenticated() {
        let (engaged, mut reader, _) = engage();
        let reader_pki = TestPki::reader();

        let doc_request =
            reader.signed_doc_request(ItemsRequest::mdl(test_namespaces()), &reader_pki, true);
        let request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(doc_request),
            device_request_info: None,
            reader_auth_all: None,
        };

        let (_, outcome) = process(
            engaged,
            &mut reader,
            &request,
            reader_pki.registry(x509::trust_anchor::TrustPurpose::ReaderCa),
        )
        .await;

        let doc_request = &outcome.doc_requests[0];
        assert!(doc_request.errors.is_empty(), "{:?}", doc_request.errors);
        assert!(doc_request.reader_auth_present);
        assert!(doc_request.is_reader_authenticated());
        assert!(doc_request.common_name.is_some());
        assert_eq!(outcome.authenticated_requested_items().len(), 1);
    }

    /// A stand-in for a non-mDL document type's reader EKU. A private-enterprise arc
    /// rather than anything under `1.0.23220`, so a plausible-looking but wrong
    /// constant cannot be copied out of a test into production.
    const TEST_READER_EKU: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.2");

    /// A reader authenticating under a non-mDL EKU passes only under its own profile.
    ///
    /// The second half is what makes this a real test: the same reader and the same
    /// anchors under [`MdocProfile::MDL`] must fail, or the first assertion would pass
    /// for the wrong reason.
    #[tokio::test]
    async fn a_non_mdl_reader_profile_is_honoured() {
        let reader_pki = TestPki::generate(
            TestPki::CRL_URL.to_string(),
            crate::definitions::x509::test::default_validity(),
            TEST_READER_EKU,
        );
        let profile = AnyDocType(MdocProfile {
            reader: ReaderProfile {
                reader_auth_eku: TEST_READER_EKU,
                ..MdocProfile::MDL.reader
            },
            ..MdocProfile::MDL
        });
        let registry = reader_pki.registry(x509::trust_anchor::TrustPurpose::ReaderCa);

        let signed_request = |reader: &mut TestReader| DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(reader.signed_doc_request(
                ItemsRequest::mdl(test_namespaces()),
                &reader_pki,
                true,
            )),
            device_request_info: None,
            reader_auth_all: None,
        };

        let (engaged, mut reader, _) = engage();
        let request = signed_request(&mut reader);
        let (_, outcome) =
            process_with_profiles(engaged, &mut reader, &request, registry.clone(), &profile).await;

        let doc_request = &outcome.doc_requests[0];
        assert!(doc_request.errors.is_empty(), "{:?}", doc_request.errors);
        assert!(doc_request.is_reader_authenticated());

        let (engaged, mut reader, _) = engage();
        let request = signed_request(&mut reader);
        let (_, outcome) = process(engaged, &mut reader, &request, registry).await;

        let doc_request = &outcome.doc_requests[0];
        assert!(!doc_request.is_reader_authenticated());
        assert!(!doc_request.errors.is_empty());
    }

    /// A doc type no profile covers is refused rather than validated under a guess.
    ///
    /// The reader is one that would otherwise authenticate cleanly, so only the empty
    /// selector can be what stops it, and the refusal is reported under its own key
    /// rather than as an authentication failure.
    #[tokio::test]
    async fn a_doc_request_without_a_profile_is_refused() {
        let reader_pki = TestPki::reader();
        let registry = reader_pki.registry(x509::trust_anchor::TrustPurpose::ReaderCa);
        let (engaged, mut reader, _) = engage();
        let request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(reader.signed_doc_request(
                ItemsRequest::mdl(test_namespaces()),
                &reader_pki,
                true,
            )),
            device_request_info: None,
            reader_auth_all: None,
        };
        let profiles: std::collections::BTreeMap<String, MdocProfile> =
            std::collections::BTreeMap::new();

        let (_, outcome) =
            process_with_profiles(engaged, &mut reader, &request, registry, &profiles).await;

        let doc_request = &outcome.doc_requests[0];
        assert!(!doc_request.is_reader_authenticated());
        assert!(
            doc_request.errors.contains_key("profile_errors"),
            "{:?}",
            doc_request.errors
        );
    }

    /// A reader authentication failure reaches the holder — a failed signature, an
    /// untrusted chain and a revoked certificate must all be distinguishable from a
    /// clean run.
    #[tokio::test]
    async fn a_bad_reader_signature_is_reported_to_the_holder() {
        let (engaged, mut reader, _) = engage();
        let reader_pki = TestPki::reader();

        let doc_request =
            reader.signed_doc_request(ItemsRequest::mdl(test_namespaces()), &reader_pki, false);
        let request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(doc_request),
            device_request_info: None,
            reader_auth_all: None,
        };

        let (_, outcome) = process(
            engaged,
            &mut reader,
            &request,
            // The chain is trusted, so the *signature* is what fails.
            reader_pki.registry(x509::trust_anchor::TrustPurpose::ReaderCa),
        )
        .await;

        let doc_request = &outcome.doc_requests[0];
        assert!(
            doc_request
                .errors
                .contains_key("reader_authentication_errors"),
            "{:?}",
            doc_request.errors
        );
        assert!(outcome.has_errors());
        assert!(doc_request.reader_auth_present);
        assert!(!doc_request.is_reader_authenticated());
    }

    /// An untrusted reader certificate is reported too, and distinguishably.
    #[tokio::test]
    async fn an_untrusted_reader_is_reported_to_the_holder() {
        let (engaged, mut reader, _) = engage();
        let reader_pki = TestPki::reader();

        let doc_request =
            reader.signed_doc_request(ItemsRequest::mdl(test_namespaces()), &reader_pki, true);
        let request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(doc_request),
            device_request_info: None,
            reader_auth_all: None,
        };

        // The signature is genuine; nothing trusts the certificate that made it.
        let (_, outcome) = process(
            engaged,
            &mut reader,
            &request,
            TrustAnchorRegistry::default(),
        )
        .await;

        let errors = &outcome.doc_requests[0].errors["reader_authentication_errors"];
        assert!(
            errors.to_string().contains("trust anchor"),
            "expected a trust anchor failure, got {errors}"
        );
    }

    /// `readerAuthAll` is detected and flagged, not silently ignored: a reader
    /// authenticating that way would otherwise look unauthenticated on every doc
    /// request.
    #[tokio::test]
    async fn reader_auth_all_is_flagged() {
        let (engaged, mut reader, _) = engage();
        let mut request = unauthenticated_request(&[MDL_DOC_TYPE]);
        request.reader_auth_all = Some(NonEmptyVec::new(
            reader
                .signed_doc_request(
                    ItemsRequest::mdl(test_namespaces()),
                    &TestPki::reader(),
                    true,
                )
                .reader_auth
                .unwrap(),
        ));

        let (_, outcome) = process(
            engaged,
            &mut reader,
            &request,
            TrustAnchorRegistry::default(),
        )
        .await;

        assert!(
            outcome.warnings.contains_key("reader_auth_all"),
            "{:?}",
            outcome.warnings
        );
    }

    /// A holder that requires reader auth still refuses a `readerAuthAll` request, because
    /// the signature cannot be verified — but the error has to say that, not claim the
    /// request carried no reader auth at all.
    #[test_log::test(tokio::test)]
    async fn reader_auth_all_is_refused_for_what_it_is() {
        let (engaged, mut reader, _) = engage();
        let mut request = unauthenticated_request(&[MDL_DOC_TYPE]);
        request.reader_auth_all = Some(NonEmptyVec::new(
            reader
                .signed_doc_request(
                    ItemsRequest::mdl(test_namespaces()),
                    &TestPki::reader(),
                    true,
                )
                .reader_auth
                .unwrap(),
        ));

        let (_, outcome) = process(
            engaged,
            &mut reader,
            &request,
            TestPki::reader().registry(x509::trust_anchor::TrustPurpose::ReaderCa),
        )
        .await;

        assert!(outcome.has_errors());
        let errors = outcome.doc_requests[0].errors["reader_authentication_errors"].to_string();
        assert!(errors.contains("readerAuthAll"), "{errors}");
        assert!(
            !errors.contains("does not contain reader auth"),
            "the error should not claim the request carried none: {errors}"
        );
    }

    /// A version the holder does not implement is reported, and the doc requests are
    /// still evaluated so the holder can show the user what was asked for.
    #[tokio::test]
    async fn an_unsupported_version_is_reported_but_doc_requests_still_evaluated() {
        let (engaged, mut reader, _) = engage();
        let mut request = unauthenticated_request(&[MDL_DOC_TYPE]);
        request.version = "0.1".to_string();

        let (_, outcome) = process(
            engaged,
            &mut reader,
            &request,
            TrustAnchorRegistry::default(),
        )
        .await;

        assert!(outcome.errors.contains_key("version_errors"));
        assert_eq!(outcome.doc_requests.len(), 1);
    }

    /// Bytes that are not CBOR are reported, *and* the holder can still return the
    /// error response the reader is waiting for.
    #[tokio::test]
    async fn an_undecodable_request_is_reported_and_an_error_response_is_retrievable() {
        let (engaged, mut reader, _) = engage();
        let establishment = reader.establishment_from_plaintext(&[0xff, 0xff, 0xff]);

        let (mut manager, outcome) = engaged
            .process_session_establishment(
                establishment,
                TrustAnchorRegistry::default(),
                &AnyDocType(MdocProfile::MDL),
                &(),
            )
            .await
            .unwrap();

        assert!(
            outcome.errors.contains_key("parsing_errors"),
            "{:?}",
            outcome.errors
        );
        // Nothing to sign, but there is still a response to send.
        assert!(manager.get_next_signature_payload().is_none());
        assert!(
            manager.retrieve_response().is_some(),
            "the holder cannot tell the reader its request was undecodable"
        );
    }

    /// The other signature-free response: the user declined to disclose anything.
    ///
    /// Same dead end as an undecodable request, but on the path a real holder hits
    /// every time a user taps "deny", so it gets its own test.
    #[tokio::test]
    async fn a_response_with_nothing_permitted_is_still_retrievable() {
        let (engaged, mut reader, _) = engage();
        let (mut manager, outcome) = process(
            engaged,
            &mut reader,
            &unauthenticated_request(&[MDL_DOC_TYPE]),
            TrustAnchorRegistry::default(),
        )
        .await;

        // Spelled out because `DeviceSession` is in scope here: `manager
        // .prepare_response(..)` would bind to the trait's `&self` method and leave
        // the session in `AwaitingRequest`.
        SessionManager::prepare_response(
            &mut manager,
            &outcome.requested_items(),
            PermittedItems::new(),
        );

        assert!(manager.get_next_signature_payload().is_none());
        assert!(
            manager.retrieve_response().is_some(),
            "the holder cannot tell the reader it declined"
        );
    }

    /// A reader that closes the session sends no data — a session event, not a
    /// parsing failure.
    #[tokio::test]
    async fn a_request_with_no_data_reports_a_session_error() {
        let (engaged, mut reader, _) = engage();
        let (mut manager, _) = process(
            engaged,
            &mut reader,
            &unauthenticated_request(&[MDL_DOC_TYPE]),
            TrustAnchorRegistry::default(),
        )
        .await;

        let closed = crate::cbor::to_vec(&SessionData {
            data: None,
            status: Some(session::Status::SessionTermination),
        })
        .unwrap();
        let outcome = manager
            .handle_request(&closed, &AnyDocType(MdocProfile::MDL), &())
            .await;

        assert!(
            outcome.errors.contains_key("session_errors"),
            "{:?}",
            outcome.errors
        );
        assert!(!outcome.errors.contains_key("parsing_errors"));
    }

    /// Data the device cannot decrypt is reported as such.
    #[tokio::test]
    async fn an_undecryptable_request_is_reported() {
        let (engaged, mut reader, _) = engage();
        let (mut manager, _) = process(
            engaged,
            &mut reader,
            &unauthenticated_request(&[MDL_DOC_TYPE]),
            TrustAnchorRegistry::default(),
        )
        .await;

        let garbage = crate::cbor::to_vec(&SessionData {
            data: Some(vec![0u8; 32].into()),
            status: None,
        })
        .unwrap();
        let outcome = manager
            .handle_request(&garbage, &AnyDocType(MdocProfile::MDL), &())
            .await;

        assert!(
            outcome.errors.contains_key("decryption_errors"),
            "{:?}",
            outcome.errors
        );
    }

    /// Well-formed CBOR that is not a `DeviceRequest` is a different failure, and
    /// gets a different status code on the wire.
    #[tokio::test]
    async fn a_valid_cbor_non_request_is_reported_separately() {
        let (engaged, mut reader, _) = engage();
        let plaintext =
            crate::cbor::to_vec(&ciborium::Value::Text("not a request".into())).unwrap();
        let establishment = reader.establishment_from_plaintext(&plaintext);

        let (_, outcome) = engaged
            .process_session_establishment(
                establishment,
                TrustAnchorRegistry::default(),
                &AnyDocType(MdocProfile::MDL),
                &(),
            )
            .await
            .unwrap();

        let reported = outcome.errors["parsing_errors"].to_string();
        assert!(
            reported.contains("not a valid DeviceRequest"),
            "expected a validation failure, got {reported}"
        );
    }
}
