mod common;

use crate::common::{Device, Reader, DOC_TYPE};

#[test_log::test(tokio::test)]
pub async fn simulated_device_and_reader_interaction() {
    let key = Device::create_signing_key().unwrap();

    // Device initialization and engagement
    let engaged_state = Device::initialise_session().unwrap();

    // Reader processing QR and requesting the necessary fields
    let (mut reader_session_manager, request) =
        Device::establish_reader_session(engaged_state.qr_handover().unwrap()).unwrap();

    // Device accepting request
    let (device_session_manager, validated_request) =
        Device::handle_request(engaged_state, request, Default::default())
            .await
            .unwrap();

    // Prepare response with required elements
    let response = Device::create_response(
        device_session_manager,
        &validated_request.requested_items(),
        &key,
    )
    .unwrap();

    // Reader Processing mDL data
    Reader::reader_handle_device_response(&mut reader_session_manager, response)
        .await
        .unwrap();
}

#[test_log::test(tokio::test)]
pub async fn simulated_device_and_reader_interaction_mac0() {
    // Device initialization and engagement
    let engaged_state = Device::initialise_session().unwrap();

    // Reader processing QR and requesting the necessary fields
    let (mut reader_session_manager, request) =
        Device::establish_reader_session(engaged_state.qr_handover().unwrap()).unwrap();

    // Device accepting request
    let (device_session_manager, validated_request) =
        Device::handle_request(engaged_state, request, Default::default())
            .await
            .unwrap();

    // Prepare response with required elements using COSE_Mac0
    let signing_key = Device::create_signing_key().unwrap();
    let response = Device::create_response_mac0(
        device_session_manager,
        &validated_request.requested_items(),
        &signing_key,
    )
    .unwrap();

    // Reader Processing mDL data
    Reader::reader_handle_device_response(&mut reader_session_manager, response)
        .await
        .unwrap();
}

/// The request side of the same exchange, asserted through the public flow.
///
/// The library's own reader sends no `readerAuth`, which is legal — so the holder must
/// see a clean outcome that nonetheless reports the reader as unauthenticated. Getting
/// this wrong in either direction (an error, or a claim of authentication) is the
/// failure mode the per-doc_request outcome exists to prevent.
#[test_log::test(tokio::test)]
pub async fn a_request_without_reader_auth_is_clean_but_unauthenticated() {
    let engaged_state = Device::initialise_session().unwrap();
    let (_, request) =
        Device::establish_reader_session(engaged_state.qr_handover().unwrap()).unwrap();

    let (_, validated_request) = Device::handle_request(engaged_state, request, Default::default())
        .await
        .unwrap();

    assert!(!validated_request.has_errors(), "{validated_request:?}");
    assert_eq!(validated_request.doc_requests.len(), 1);

    let doc_request = &validated_request.doc_requests[0];
    assert_eq!(doc_request.items_request.doc_type, DOC_TYPE);
    assert!(!doc_request.reader_auth_present);
    assert!(!doc_request.is_reader_authenticated());
    assert!(doc_request.common_name.is_none());

    // So a holder that requires an authenticated reader has nothing to disclose.
    assert!(validated_request.authenticated_requested_items().is_empty());
    assert_eq!(validated_request.requested_items().len(), 1);
}
