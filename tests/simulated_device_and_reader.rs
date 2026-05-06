mod common;

use crate::common::{Device, Reader};
use isomdl::definitions::device_request::{DataElements, Namespaces, RequestedDocuments};
use isomdl::definitions::x509::{
    trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose},
    X5Chain,
};
use isomdl::presentation::authentication::AuthenticationStatus;
use isomdl::presentation::reader;

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
        &validated_request.items_request,
        &key,
    )
    .unwrap();

    // Reader Processing mDL data
    Reader::reader_handle_device_response(&mut reader_session_manager, response)
        .await
        .unwrap();
}

#[test_log::test(tokio::test)]
pub async fn simulated_device_and_reader_with_reader_auth() {
    let reader_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let reader_cert = common::build_test_reader_cert(&reader_key).unwrap();
    let x5chain = X5Chain::builder()
        .with_certificate(reader_cert.clone())
        .unwrap()
        .build()
        .unwrap();
    let reader_trust_anchors = TrustAnchorRegistry {
        anchors: vec![TrustAnchor {
            certificate: reader_cert,
            purpose: TrustPurpose::ReaderCa,
        }],
    };

    // Device initialization and engagement
    let engaged_state = Device::initialise_session().unwrap();
    let qr = engaged_state.qr_handover().unwrap();

    let namespaces = Namespaces::new(
        common::NAMESPACE.into(),
        DataElements::new(common::AGE_OVER_21_ELEMENT.to_string(), false),
    );

    // Reader establishes a signed session (reader authentication)
    let (mut reader_sm, request, _) =
        reader::SessionManager::establish_session_multi_signed::<_, p256::ecdsa::Signature>(
            reader::Handover::QR(qr),
            RequestedDocuments::new(common::DOC_TYPE.to_string(), namespaces),
            TrustAnchorRegistry::default(),
            &reader_key,
            x5chain,
        )
        .await
        .unwrap();

    // Device accepts request and validates reader authentication against the reader CA
    let (device_sm, validated) =
        Device::handle_request(engaged_state, request, reader_trust_anchors)
            .await
            .unwrap();

    assert_eq!(validated.reader_authentication, AuthenticationStatus::Valid);

    // Verify the full flow still completes correctly
    let key = Device::create_signing_key().unwrap();
    let response = Device::create_response(device_sm, &validated.items_request, &key).unwrap();
    Reader::reader_handle_device_response(&mut reader_sm, response)
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
        &validated_request.items_request,
        &signing_key,
    )
    .unwrap();

    // Reader Processing mDL data
    Reader::reader_handle_device_response(&mut reader_session_manager, response)
        .await
        .unwrap();
}
