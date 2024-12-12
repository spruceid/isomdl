use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use isomdl::cbor;
use isomdl::definitions::device_engagement::{CentralClientMode, DeviceRetrievalMethods};
use isomdl::definitions::device_request::{DataElements, Namespaces};
use isomdl::definitions::{self, BleOptions, DeviceRetrievalMethod};
use isomdl::presentation::device::{Documents, RequestedItems};
use isomdl::presentation::{device, reader};
use signature::Signer;
use uuid::Uuid;

use crate::common::{Device, AGE_OVER_21_ELEMENT, DOC_TYPE, NAMESPACE};

mod common;

struct SessionData {
    state: Arc<SessionManagerEngaged>,
    qr_code_uri: String,
}

struct RequestData {
    session_manager: Arc<SessionManager>,
}

struct SessionManager {
    inner: Mutex<device::SessionManager>,
    items_request: RequestedItems,
    key: Arc<p256::ecdsa::SigningKey>,
}

struct SessionManagerEngaged(device::SessionManagerEngaged);

#[test]
pub fn simulated_device_and_reader_interaction() -> Result<()> {
    let key: Arc<p256::ecdsa::SigningKey> =
        Arc::new(p256::SecretKey::from_sec1_pem(include_str!("data/sec1.pem"))?.into());

    // Parse the mDL
    let docs = Device::parse_mdl()?;

    // Device initialization and engagement
    let session_data = initialise_session(docs, Uuid::new_v4())?;

    // Reader processing QR and requesting the necessary fields
    let (mut reader_session_manager, request) = establish_reader_session(session_data.qr_code_uri)?;

    // Device accepting request
    let request_data = handle_request(
        session_data.state,
        &mut reader_session_manager,
        request,
        key.clone(),
    )?;
    if request_data.is_none() {
        anyhow::bail!("there were errors processing request");
    }
    let request_data = request_data.unwrap();

    // Prepare response with required elements
    let response = create_response(request_data.session_manager.clone())?;

    // Reader Processing mDL data
    reader_handle_device_response(&mut reader_session_manager, response)?;

    Ok(())
}

/// Check if there were any errors and sign them if needed, returning the response error.
fn get_errors(session_manager: Arc<SessionManager>) -> Result<Option<Vec<u8>>> {
    sign_pending_and_retrieve_response(session_manager, None)
}

/// Creates a QR code containing `DeviceEngagement` data, which includes its public key.
fn initialise_session(docs: Documents, uuid: Uuid) -> Result<SessionData> {
    let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
        peripheral_server_mode: None,
        central_client_mode: Some(CentralClientMode { uuid }),
    }));

    let session = device::SessionManagerInit::initialise(docs, Some(drms), None)
        .context("failed to initialize device")?;

    let (engaged_state, qr_code_uri) = session
        .qr_engagement()
        .context("could not generate qr engagement")?;
    Ok(SessionData {
        state: Arc::new(SessionManagerEngaged(engaged_state)),
        qr_code_uri,
    })
}

/// Establishes the reader session from the given QR code and create request for needed elements.
fn establish_reader_session(qr: String) -> Result<(reader::SessionManager, Vec<u8>)> {
    let requested_elements = Namespaces::new(
        NAMESPACE.into(),
        DataElements::new(AGE_OVER_21_ELEMENT.to_string(), false),
    );
    let trust_anchor_registry = None; // Option<TrustAnchorRegistry>,;

    let (reader_sm, session_request, _ble_ident) =
        reader::SessionManager::establish_session(qr, requested_elements, trust_anchor_registry)
            .context("failed to establish reader session")?;
    Ok((reader_sm, session_request))
}

/// The Device handles the request from the reader and creates the `RequestData` context.
fn handle_request(
    state: Arc<SessionManagerEngaged>,
    reader_session_manager: &mut reader::SessionManager,
    request: Vec<u8>,
    key: Arc<p256::ecdsa::SigningKey>,
) -> Result<Option<RequestData>> {
    let (session_manager, validated_response) = {
        let session_establishment: definitions::SessionEstablishment =
            cbor::from_slice(&request).context("could not deserialize request")?;
        state
            .0
            .clone()
            .process_session_establishment(session_establishment, None)
            .context("could not process process session establishment")?
    };
    let session_manager = Arc::new(SessionManager {
        inner: Mutex::new(session_manager),
        items_request: validated_response.items_request.clone(),
        key,
    });
    // Propagate any errors back to the reader
    if let Ok(Some(response)) = get_errors(session_manager.clone()) {
        let validated_response = reader_session_manager.handle_response(&response);
        println!("Reader: {validated_response:?}");
        return Ok(None);
    };

    Ok(Some(RequestData { session_manager }))
}

// Prepare response with required elements.
fn create_response(session_manager: Arc<SessionManager>) -> Result<Vec<u8>> {
    let permitted_items = [(
        DOC_TYPE.to_string(),
        [(NAMESPACE.to_string(), vec![AGE_OVER_21_ELEMENT.to_string()])]
            .into_iter()
            .collect(),
    )]
    .into_iter()
    .collect();
    session_manager
        .inner
        .lock()
        .unwrap()
        .prepare_response(&session_manager.items_request, permitted_items);
    sign_pending_and_retrieve_response(session_manager.clone(), Some(1))?
        .ok_or_else(|| anyhow::anyhow!("cannot prepare response"))
}

fn sign_pending_and_retrieve_response(
    session_manager: Arc<SessionManager>,
    expected_to_sign: Option<usize>,
) -> Result<Option<Vec<u8>>> {
    let mut signed = 0;
    loop {
        let mut guard = session_manager.inner.lock().unwrap();
        if let Some((_, payload)) = guard.get_next_signature_payload() {
            if let Some(expected_to_sign) = expected_to_sign {
                if signed >= expected_to_sign {
                    anyhow::bail!(
                        "expected to sign {} documents, but there are more",
                        expected_to_sign
                    );
                }
            }
            let signature: p256::ecdsa::Signature = session_manager.key.sign(payload);
            guard
                .submit_next_signature(signature.to_vec())
                .context("failed to submit signature")?;
            signed += 1;
        } else {
            break;
        }
    }
    Ok(session_manager.inner.lock().unwrap().retrieve_response())
}

/// Reader Processing mDL data.
fn reader_handle_device_response(
    reader_sm: &mut reader::SessionManager,
    response: Vec<u8>,
) -> Result<()> {
    let validated_response = reader_sm.handle_response(&response);
    println!("Validated Response: {validated_response:?}");
    Ok(())
}
