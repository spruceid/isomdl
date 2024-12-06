#![allow(dead_code)]
use anyhow::{anyhow, Context, Result};
use isomdl::cbor;
use isomdl::definitions::device_engagement::{CentralClientMode, DeviceRetrievalMethods};
use isomdl::definitions::device_request::{DataElements, DocType, Namespaces};
use isomdl::definitions::helpers::NonEmptyMap;
use isomdl::definitions::validated_request::ValidatedRequest;
use isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry;
use isomdl::definitions::x509::X5Chain;
use isomdl::definitions::{self, BleOptions, DeviceRetrievalMethod};
use isomdl::presentation::device::{Document, Documents, RequestedItems, SessionManagerEngaged};
use isomdl::presentation::{device, reader, Stringify};
use signature::Signer;
use uuid::Uuid;

pub const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
pub const NAMESPACE: &str = "org.iso.18013.5.1";
pub const AGE_OVER_21_ELEMENT: &str = "age_over_21";

pub struct Device {}

impl Device {
    /// Parse the mDL encoded string into a [Documents] object.
    pub fn parse_mdl() -> Result<NonEmptyMap<DocType, Document>> {
        let mdl_encoded = include_str!("data/stringified-mdl.txt");
        let mdl = Document::parse(mdl_encoded.to_string()).context("could not parse mDL")?;
        let docs = Documents::new(DOC_TYPE.to_string(), mdl);
        Ok(docs)
    }

    /// Creates a QR code containing `DeviceEngagement` data, which includes its public key.
    pub fn initialise_session() -> Result<(SessionManagerEngaged, String)> {
        // Parse the mDL
        let docs = Device::parse_mdl()?;

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
    pub fn establish_reader_session(qr: String) -> Result<(reader::SessionManager, Vec<u8>)> {
        let requested_elements = Namespaces::new(
            NAMESPACE.into(),
            DataElements::new(AGE_OVER_21_ELEMENT.to_string(), false),
        );

        let trust_anchor = None;
        let reader_x5chain =
            // NOTE: Should we be using a different certificate here for the reader?
            // I didn't see one in the test data.
            X5Chain::builder().with_der(include_bytes!("../test/issuance/256-cert.der"))?.build()?;
        // TODO: We should be using a typed key to pass to establish the session below instead of &str.
        // let reader_key = p256::ecdsa::SigningKey::from_sec1_pem(include_str!("data/sec1.pem"))?;
        let reader_key = include_str!("data/sec1.pem");

        let (reader_sm, session_request, _ble_ident) = reader::SessionManager::establish_session(
            qr,
            requested_elements,
            trust_anchor,
            reader_x5chain,
            reader_key,
        )
        .context("failed to establish reader session")?;
        Ok((reader_sm, session_request))
    }

    /// The Device handles the request from the reader and advances the state.
    pub fn handle_request(
        state: SessionManagerEngaged,
        request: Vec<u8>,
        trusted_verifiers: Option<TrustAnchorRegistry>,
    ) -> Result<(device::SessionManager, ValidatedRequest)> {
        let (session_manager, validated_request) = {
            let session_establishment: definitions::SessionEstablishment =
                cbor::from_slice(&request).context("could not deserialize request")?;
            state
                .process_session_establishment(session_establishment, trusted_verifiers)
                .context("could not process process session establishment")?
        };
        if session_manager.get_next_signature_payload().is_some() {
            anyhow::bail!("there were errors processing request");
        }
        Ok((session_manager, validated_request))
    }

    /// Prepare response with required elements.
    pub fn create_response(
        mut session_manager: device::SessionManager,
        requested_items: &RequestedItems,
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
        session_manager.prepare_response(requested_items, permitted_items);
        let (_, sign_payload) = session_manager.get_next_signature_payload().unwrap();
        let signature: p256::ecdsa::Signature = key.sign(sign_payload);
        session_manager
            .submit_next_signature(signature.to_vec())
            .context("failed to submit signature")?;
        session_manager
            .retrieve_response()
            .ok_or(anyhow!("cannot prepare response"))
    }

    pub fn create_signing_key() -> Result<p256::ecdsa::SigningKey> {
        Ok(p256::SecretKey::from_sec1_pem(include_str!("data/sec1.pem"))?.into())
    }
}

pub struct Reader {}

impl Reader {
    /// Reader Processing mDL data.
    pub fn reader_handle_device_response(
        reader_sm: &mut reader::SessionManager,
        response: Vec<u8>,
    ) -> Result<()> {
        let validated = reader_sm.handle_response(&response);
        println!("Validated Response: {validated:?}");
        Ok(())
    }
}
