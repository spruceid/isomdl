use anyhow::{anyhow, Context, Result};
use signature::Signer;
use uuid::Uuid;

use isomdl::definitions::device_engagement::{CentralClientMode, DeviceRetrievalMethods};
use isomdl::definitions::device_request::{DataElements, DocType, Namespaces};
use isomdl::definitions::helpers::NonEmptyMap;
use isomdl::definitions::{self, BleOptions, DeviceRetrievalMethod};
use isomdl::presentation::device::{Document, Documents, RequestedItems, SessionManagerEngaged};
use isomdl::presentation::{device, reader, Stringify};

#[allow(dead_code)]
const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const NAMESPACE: &str = "org.iso.18013.5.1";
const AGE_OVER_21_ELEMENT: &str = "age_over_21";

#[allow(dead_code)]
fn main() {}

/// Parse the mDL encoded string into a [Documents] object.
#[allow(dead_code)]
pub fn parse_mdl() -> Result<NonEmptyMap<DocType, Document>> {
    let mdl_encoded = include_str!("data/stringified-mdl.txt");
    let mdl = Document::parse(mdl_encoded.to_string()).context("could not parse mDL")?;
    let docs = Documents::new(crate::DOC_TYPE.to_string(), mdl);
    Ok(docs)
}

/// Creates a QR code containing `DeviceEngagement` data, which includes its public key.
#[allow(dead_code)]
pub fn initialise_session() -> Result<(SessionManagerEngaged, String)> {
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

/// Establishes the reader session from the given QR code and create request for needed elements.
#[allow(dead_code)]
pub fn establish_reader_session(qr: String) -> Result<(reader::SessionManager, Vec<u8>)> {
    let requested_elements = Namespaces::new(
        NAMESPACE.into(),
        DataElements::new(AGE_OVER_21_ELEMENT.to_string(), false),
    );
    let (reader_sm, session_request, _ble_ident) =
        reader::SessionManager::establish_session(qr, requested_elements)
            .context("failed to establish reader session")?;
    Ok((reader_sm, session_request))
}

/// The Device handles the request from the reader and advances the state.
#[allow(dead_code)]
pub fn handle_request(
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
#[allow(dead_code)]
pub fn create_response(
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

/// Reader Processing mDL data.
#[allow(dead_code)]
pub fn reader_handle_device_response(
    reader_sm: &mut reader::SessionManager,
    response: Vec<u8>,
) -> Result<()> {
    let res = reader_sm.handle_response(&response)?;
    println!("{:?}", res);
    Ok(())
}

#[allow(dead_code)]
pub fn create_signing_key() -> Result<p256::ecdsa::SigningKey> {
    Ok(p256::SecretKey::from_sec1_pem(include_str!("data/sec1.pem"))?.into())
}
