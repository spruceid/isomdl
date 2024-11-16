mod common;

use crate::common::{Device, Reader};

use anyhow::Result;

#[test]
pub fn simulated_device_and_reader_interaction() -> Result<()> {
    let key: p256::ecdsa::SigningKey =
        p256::SecretKey::from_sec1_pem(include_str!("data/sec1.pem"))?.into();

    // Device initialization and engagement
    let (engaged_state, qr_code_uri) = Device::initialise_session()?;

    // Reader processing QR and requesting the necessary fields
    let (mut reader_session_manager, request) = Device::establish_reader_session(qr_code_uri)?;

    // Device accepting request
    let (device_session_manager, validated_request) =
        Device::handle_request(engaged_state, request, None)?;

    // Prepare response with required elements
    let response = Device::create_response(
        device_session_manager,
        &validated_request.items_request,
        &key,
    )?;

    // Reader Processing mDL data
    Reader::reader_handle_device_response(&mut reader_session_manager, response)?;

    Ok(())
}
