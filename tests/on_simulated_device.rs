mod common;

use anyhow::{anyhow, Context, Result};
use signature::Signer;
use uuid::Uuid;

use isomdl::definitions;
use isomdl::definitions::device_engagement::{CentralClientMode, DeviceRetrievalMethods};
use isomdl::definitions::device_request::DocType;
use isomdl::definitions::helpers::NonEmptyMap;
use isomdl::definitions::{BleOptions, DeviceRetrievalMethod};
use isomdl::presentation::device::{Document, Documents, RequestedItems, SessionManagerEngaged};
use isomdl::presentation::{device, Stringify};

use crate::common::{establish_reader_session, reader_handle_device_response};

const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const NAMESPACE: &str = "org.iso.18013.5.1";
const AGE_OVER_21_ELEMENT: &str = "age_over_21";

fn main() {}

#[test]
fn on_simulated_device() -> Result<()> {
    // Device initialization and engagement
    let (engaged_state, qr_code_uri) = initialise_session()?;

    // Reader processing QR and requesting the necessary fields
    let (mut reader_session_manager, request) = establish_reader_session(qr_code_uri)?;

    // Device accepting request
    let (device_session_manager, requested_items) = handle_request(engaged_state, request)?;

    // Prepare response with required elements
    let response = create_response(
        device_session_manager,
        requested_items,
        &create_signing_key()?,
    )?;

    // Reader Processing mDL data
    reader_handle_device_response(&mut reader_session_manager, response)?;

    Ok(())
}

/// Parse the mDL encoded string into a [Documents] object.
fn parse_mdl() -> Result<NonEmptyMap<DocType, Document>> {
    let mdl_encoded = include_str!("data/stringified-mdl.txt");
    let mdl = Document::parse(mdl_encoded.to_string()).context("could not parse mDL")?;
    let docs = Documents::new(DOC_TYPE.to_string(), mdl);
    Ok(docs)
}

/// Creates a QR code containing `DeviceEngagement` data, which includes its public key.
fn initialise_session() -> Result<(SessionManagerEngaged, String)> {
    // Parse the mDL
    let docs = parse_mdl()?;

    let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
        peripheral_server_mode: None,
        central_client_mode: Some(CentralClientMode {
            uuid: Uuid::new_v4(),
        }),
    }));

    let session = device::SessionManagerInit::initialise(docs, Some(drms), None)
        .context("failed to initialize device")?;

    session
        .qr_engagement()
        .context("could not generate qr engagement")
}

/// The Device handles the request from the reader and advances the state.
fn handle_request(
    state: SessionManagerEngaged,
    request: Vec<u8>,
) -> Result<(device::SessionManager, RequestedItems)> {
    let (session_manager, items_requests) = {
        let session_establishment: definitions::SessionEstablishment =
            serde_cbor::from_slice(&request).context("could not deserialize request")?;
        state
            .process_session_establishment(session_establishment)
            .context("could not process process session establishment")?
    };
    if session_manager.get_next_signature_payload().is_some() {
        anyhow::bail!("there were errors processing request");
    }
    Ok((session_manager, items_requests))
}

/// Prepare response with required elements.
fn create_response(
    mut session_manager: device::SessionManager,
    requested_items: RequestedItems,
    key: &p256::ecdsa::SigningKey,
) -> Result<Vec<u8>> {
    let permitted_items = [(
        DOC_TYPE.to_string(),
        [(NAMESPACE.to_string(), vec![AGE_OVER_21_ELEMENT.to_string()])]
            .into_iter()
            .collect(),
    )]
    .into_iter()
    .collect();
    session_manager.prepare_response(&requested_items, permitted_items);
    let (_, sign_payload) = session_manager.get_next_signature_payload().unwrap();
    let signature: p256::ecdsa::Signature = key.sign(sign_payload);
    session_manager
        .submit_next_signature(signature.to_vec())
        .context("failed to submit signature")?;
    session_manager
        .retrieve_response()
        .ok_or(anyhow!("cannot prepare response"))
}

fn create_signing_key() -> Result<p256::ecdsa::SigningKey> {
    Ok(p256::SecretKey::from_sec1_pem(include_str!("data/sec1.pem"))?.into())
}
