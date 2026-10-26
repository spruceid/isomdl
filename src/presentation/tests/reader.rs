use super::*;

#[test]
fn nested_response_values() {
    let domestic_driving_privileges = crate::cbor::from_slice(&hex::decode("81A276646F6D65737469635F76656869636C655F636C617373A46A69737375655F64617465D903EC6A323032342D30322D31346B6578706972795F64617465D903EC6A323032382D30332D3131781B646F6D65737469635F76656869636C655F636C6173735F636F64656243207822646F6D65737469635F76656869636C655F636C6173735F6465736372697074696F6E76436C6173732043204E4F4E2D434F4D4D45524349414C781D646F6D65737469635F76656869636C655F7265737472696374696F6E7381A27821646F6D65737469635F76656869636C655F7265737472696374696F6E5F636F64656230317828646F6D65737469635F76656869636C655F7265737472696374696F6E5F6465736372697074696F6E78284D555354205745415220434F5252454354495645204C454E534553205748454E2044524956494E47").unwrap()).unwrap();
    let json = parse_response(domestic_driving_privileges).unwrap();
    let expected = serde_json::json!(
      [
        {
          "domestic_vehicle_class": {
            "issue_date": "2024-02-14",
            "expiry_date": "2028-03-11",
            "domestic_vehicle_class_code": "C ",
            "domestic_vehicle_class_description": "Class C NON-COMMERCIAL"
          },
          "domestic_vehicle_restrictions": [
            {
              "domestic_vehicle_restriction_code": "01",
              "domestic_vehicle_restriction_description": "MUST WEAR CORRECTIVE LENSES WHEN DRIVING"
            }
          ]
        }
      ]
    );
    assert_eq!(json, expected)
}

/// The reader must remember every doc type it has asked for, across calls.
///
/// The union matters: `new_request` is callable repeatedly, and a holder answering
/// an earlier request is not sending an unsolicited credential.
#[test]
fn requested_doc_types_accumulate_across_requests() {
    use crate::definitions::device_request::{DataElements, ItemsRequest, Namespaces};

    fn ns() -> Namespaces {
        Namespaces::new(
            "org.iso.18013.5.1".to_string(),
            DataElements::new("age_over_21".to_string(), false),
        )
    }

    let (mut manager, _, _) = SessionManager::establish_session(
        Handover::QR(test_qr_engagement()),
        NonEmptyVec::new(ItemsRequest::mdl(ns())),
        TrustAnchorRegistry::default(),
    )
    .unwrap();

    assert_eq!(
        manager.requested_doc_types(),
        Some(&BTreeSet::from([
            crate::definitions::MDL_DOC_TYPE.to_string()
        ]))
    );

    manager
        .new_request(NonEmptyVec::new(ItemsRequest::new(
            "org.iso.23220.photoid.1",
            ns(),
        )))
        .unwrap();

    assert_eq!(
        manager.requested_doc_types(),
        Some(&BTreeSet::from([
            crate::definitions::MDL_DOC_TYPE.to_string(),
            "org.iso.23220.photoid.1".to_string(),
        ])),
        "the earlier request was forgotten"
    );
}

/// A response that will not decode yields no documents *and* says why.
///
/// The third and last path that can produce `documents: None` — it is shared with
/// the decryption failure, which returns from the same place. Since the struct's
/// fields are independent, nothing but a test stops this one from returning an
/// outcome that reads as "nothing wrong" to a consumer checking `errors`.
#[tokio::test]
async fn an_undecodable_response_reports_a_reason() {
    use crate::definitions::device_request::{DataElements, ItemsRequest, Namespaces};

    let (mut manager, _, _) = SessionManager::establish_session(
        Handover::QR(test_qr_engagement()),
        NonEmptyVec::new(ItemsRequest::mdl(Namespaces::new(
            "org.iso.18013.5.1".to_string(),
            DataElements::new("age_over_21".to_string(), false),
        ))),
        TrustAnchorRegistry::default(),
    )
    .unwrap();

    let outcome = manager
        .handle_response(
            b"not a session data cbor",
            &crate::definitions::x509::validation::AnyDocType(
                crate::definitions::x509::validation::MdocProfile::MDL,
            ),
            &(),
        )
        .await;

    assert!(outcome.documents.is_empty());
    assert!(
        outcome
            .errors
            .iter()
            .any(|e| matches!(e, ResponseError::CborDecoding { .. })),
        "{:?}",
        outcome.errors
    );
}

/// A session persisted before `requested_doc_types` existed must still deserialize.
///
/// Consumers keep this struct in a database across deploys. Without
/// `#[serde(default)]` every session in flight when the new version ships would fail
/// to load — so this is a compatibility guarantee, not a nicety. Such a session has
/// no filter, and the outcome says so via `RequestedDocTypesUnknown`.
#[test]
fn a_session_persisted_without_the_new_field_still_deserializes() {
    use crate::definitions::device_request::{DataElements, ItemsRequest, Namespaces};

    let (manager, _, _) = SessionManager::establish_session(
        Handover::QR(test_qr_engagement()),
        NonEmptyVec::new(ItemsRequest::mdl(Namespaces::new(
            "org.iso.18013.5.1".to_string(),
            DataElements::new("age_over_21".to_string(), false),
        ))),
        TrustAnchorRegistry::default(),
    )
    .unwrap();

    // Persistence goes through CBOR (see `Stringify`), so the old state is modelled
    // by dropping the key from the encoded map — exactly what a row written by the
    // previous version looks like.
    let encoded = cbor::to_vec(&manager).unwrap();
    let mut persisted: ciborium::Value = cbor::from_slice(&encoded).unwrap();
    let ciborium::Value::Map(entries) = &mut persisted else {
        panic!("a struct should encode as a CBOR map");
    };
    let before = entries.len();
    entries.retain(|(key, _)| key != &ciborium::Value::Text("requested_doc_types".into()));
    assert_eq!(
        entries.len(),
        before - 1,
        "the field should have been serialized in the first place"
    );

    let restored: SessionManager = cbor::from_slice(&cbor::to_vec(&persisted).unwrap()).unwrap();
    assert_eq!(restored.requested_doc_types(), None);
}

/// A QR engagement from a real device session, for the reader tests above.
fn test_qr_engagement() -> String {
    use crate::definitions::helpers::NonEmptyMap;
    use crate::definitions::x509::test::TestPki;
    use crate::issuance::mdoc::test::{issue_test_mdoc, valid_for_a_year, MDL_DOC_TYPE};
    use crate::presentation::device::{Document, SessionManagerInit};

    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year()).unwrap();
    let documents = NonEmptyMap::new(mdoc.doc_type.clone(), Document::from(mdoc));

    SessionManagerInit::initialise(documents, None, None)
        .unwrap()
        .engage(crate::definitions::session::Handover::QR)
        .unwrap()
        .qr_handover()
        .unwrap()
}
