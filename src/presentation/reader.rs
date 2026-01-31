//! This module is responsible for the reader's interaction with the device.
//!
//! It handles this through [SessionManager] state
//! which is responsible for handling the session with the device.
//!
//! From the reader's perspective, the flow is as follows:
//!
//! ```ignore
#![doc = include_str!("../../docs/on_simulated_reader.txt")]
//! ```
//!
//! ### Example
//!
//! You can view examples in `tests` directory in `simulated_device_and_reader.rs`, for a basic example and
//! `simulated_device_and_reader_state.rs` which uses `State` pattern, `Arc` and `Mutex`.
use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use coset::Label;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::{authentication::ResponseAuthenticationOutcome, reader_utils::validate_response};

use crate::definitions::x509::crl::CrlFetcher;

use crate::{
    cbor::{self, CborError},
    definitions::{
        device_engagement::{
            nfc::{LeRole, ReaderNegotiatedCarrierInfo},
            BleMode, CentralClientMode, PeripheralServerMode,
        },
        device_key::cose_key::Error as CoseError,
        device_request::{
            self, DeviceRequest, DeviceRequestInfoBytes, DocRequest, ItemsRequest,
            ItemsRequestBytesAll,
        },
        device_response::Document,
        helpers::{non_empty_vec, NonEmptyVec, Tag24},
        session::{
            self, create_p256_ephemeral_keys, derive_session_key, get_shared_secret,
            SessionEstablishment,
        },
        x509::{trust_anchor::TrustAnchorRegistry, x5chain::X5CHAIN_COSE_HEADER_LABEL, X5Chain},
        DeviceEngagement, DeviceResponse, SessionData, SessionTranscript180135,
    },
    presentation::reader::{device_request::ItemsRequestBytes, Error as ReaderError},
};

/// The main state of the reader.
///
/// The reader's [SessionManager] state machine is responsible
/// for handling the session with the device.
///
/// The transition to this state is made by [SessionManager::establish_session].
#[derive(Serialize, Deserialize, Clone)]
pub struct SessionManager {
    session_transcript: SessionTranscript180135,
    sk_device: [u8; 32],
    device_message_counter: u32,
    sk_reader: [u8; 32],
    reader_message_counter: u32,
    trust_anchor_registry: TrustAnchorRegistry,
    holder_le_role: Option<LeRole>,
    holder_central_client_modes: Vec<CentralClientMode>,
    holder_peripheral_server_modes: Vec<PeripheralServerMode>,
}

#[derive(Serialize, Deserialize)]
pub struct ReaderAuthentication(
    pub String,
    pub SessionTranscript180135,
    pub ItemsRequestBytes,
);

#[derive(Serialize, Deserialize)]
pub struct ReaderAuthenticationAll<S>(
    pub String,
    /// Meant to be the SessionTranscript
    pub S,
    pub ItemsRequestBytesAll,
    pub Option<DeviceRequestInfoBytes>,
);

/// Various errors that can occur during the interaction with the device.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Received IssuerAuth had a detached payload.")]
    DetachedIssuerAuth,
    #[error("Could not parse MSO.")]
    MSOParsing,
    /// The QR code had the wrong prefix or the contained data could not be decoded.
    #[error("the qr code had the wrong prefix or the contained data could not be decoded: {0}")]
    InvalidQrCode(anyhow::Error),
    /// Device did not transmit any data.
    #[error("Device did not transmit any data.")]
    DeviceTransmissionError,
    /// Device did not transmit an mDL.
    #[error("Device did not transmit an mDL.")]
    DocumentTypeError,
    /// The device did not transmit any mDL data.
    #[error("the device did not transmit any mDL data.")]
    NoMdlDataTransmission,
    /// Device did not transmit any data in the `org.iso.18013.5.1` namespace.
    #[error("device did not transmit any data in the org.iso.18013.5.1 namespace.")]
    IncorrectNamespace,
    /// The Device responded with an error.
    #[error("device responded with an error.")]
    HolderError,
    /// Could not decrypt the response.
    #[error("could not decrypt the response.")]
    DecryptionError,
    /// Unexpected CBOR type for offered value.
    #[error("Unexpected CBOR type for offered value")]
    CborDecodingError,
    /// Not a valid JSON input.
    #[error("not a valid JSON input.")]
    JsonError,
    /// Unexpected data type for data element.
    #[error("Unexpected data type for data element: {0}.")]
    ParsingError(String),
    /// Request for data is invalid.
    #[error("Request for data is invalid.")]
    InvalidRequest,
    #[error("Failed mdoc authentication: {0}")]
    MdocAuth(String),
    #[error("Currently unsupported format")]
    Unsupported,
    #[error("No x5chain found for issuer authentication")]
    X5ChainMissing,
    #[error("Failed to parse x5chain: {0}")]
    X5ChainParsing(anyhow::Error),
    #[error("issuer authentication failed: {0}")]
    IssuerAuthentication(String),
    #[error("Unable to parse issuer public key")]
    IssuerPublicKey(anyhow::Error),
}

impl From<CborError> for Error {
    fn from(_: CborError) -> Self {
        Error::CborDecodingError
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::JsonError
    }
}

impl From<x509_cert::der::Error> for Error {
    fn from(value: x509_cert::der::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<p256::ecdsa::Error> for Error {
    fn from(value: p256::ecdsa::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<x509_cert::spki::Error> for Error {
    fn from(value: x509_cert::spki::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<CoseError> for Error {
    fn from(value: CoseError) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<non_empty_vec::Error> for Error {
    fn from(value: non_empty_vec::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<asn1_rs::Error> for Error {
    fn from(value: asn1_rs::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Handover {
    QR(String),
    NFC(Box<ReaderNegotiatedCarrierInfo>),
}

impl SessionManager {
    /// Establish a session with the device.
    ///
    /// Internally it generates the ephemeral keys,
    /// derives the shared secret, and derives the session keys
    /// (using **Diffie–Hellman key exchange**).
    pub fn establish_session(
        handover: Handover,
        namespaces: device_request::Namespaces,
        trust_anchor_registry: TrustAnchorRegistry,
    ) -> Result<(Self, Vec<u8>, [u8; 16])> {
        let (
            device_engagement_bytes,
            session_transcript_handover,
            holder_le_role,
            holder_central_client_modes,
            holder_peripheral_server_modes,
        ) = match handover {
            Handover::NFC(carrier_info) => {
                let device_engagement_bytes = Tag24::new(carrier_info.device_engagement)
                    .context("Failed to build tag24 device engagement")?;
                let le_role = Some(carrier_info.holder_le_role);
                let uuid = carrier_info.uuid;
                let central_client_modes: Vec<_> = device_engagement_bytes
                    .as_ref()
                    .ble_central_client_options()
                    .cloned()
                    .collect();
                let peripheral_server_modes: Vec<_> = device_engagement_bytes
                    .as_ref()
                    .ble_peripheral_server_options()
                    .cloned()
                    .collect();
                let central_client_modes = if central_client_modes.is_empty() {
                    vec![CentralClientMode { uuid }]
                } else {
                    central_client_modes
                };
                let peripheral_server_modes = if peripheral_server_modes.is_empty() {
                    vec![PeripheralServerMode {
                        uuid,
                        ble_device_address: carrier_info.ble_device_address,
                    }]
                } else {
                    peripheral_server_modes
                };
                (
                    device_engagement_bytes,
                    crate::definitions::session::Handover::NFC(
                        carrier_info.hs_message,
                        carrier_info.hr_message,
                    ),
                    le_role,
                    central_client_modes,
                    peripheral_server_modes,
                )
            }
            Handover::QR(qr_code) => {
                let device_engagement_bytes = Tag24::<DeviceEngagement>::from_qr_code_uri(&qr_code)
                    .context("failed to construct QR code")?;
                let le_role = None;
                let central_client_modes = device_engagement_bytes
                    .as_ref()
                    .ble_central_client_options()
                    .cloned()
                    .collect();
                let peripheral_server_modes = device_engagement_bytes
                    .as_ref()
                    .ble_peripheral_server_options()
                    .cloned()
                    .collect();
                (
                    device_engagement_bytes,
                    crate::definitions::session::Handover::QR,
                    le_role,
                    central_client_modes,
                    peripheral_server_modes,
                )
            }
        };

        //generate own keys
        let key_pair = create_p256_ephemeral_keys().context("failed to generate ephemeral key")?;
        let e_reader_key_private = key_pair.0;
        let e_reader_key_public =
            Tag24::new(key_pair.1).context("failed to encode public cose key")?;

        //decode device_engagement
        let device_engagement = device_engagement_bytes.as_ref();
        let e_device_key = &device_engagement.security.1;

        // calculate ble Ident value
        let ble_ident =
            super::calculate_ble_ident(e_device_key).context("failed to calculate BLE Ident")?;

        // derive shared secret
        let shared_secret = get_shared_secret(
            e_device_key.clone().into_inner(),
            &e_reader_key_private.into(),
        )
        .context("failed to derive shared session secret")?;

        let session_transcript = SessionTranscript180135(
            device_engagement_bytes,
            e_reader_key_public.clone(),
            session_transcript_handover,
        );

        let session_transcript_bytes = Tag24::new(session_transcript.clone())
            .context("failed to encode session transcript")?;

        //derive session keys
        let sk_reader = derive_session_key(&shared_secret, &session_transcript_bytes, true)
            .context("failed to derive reader session key")?
            .into();
        let sk_device = derive_session_key(&shared_secret, &session_transcript_bytes, false)
            .context("failed to derive device session key")?
            .into();

        let mut session_manager = Self {
            session_transcript,
            sk_device,
            device_message_counter: 0,
            sk_reader,
            reader_message_counter: 0,
            trust_anchor_registry,
            holder_le_role,
            holder_central_client_modes,
            holder_peripheral_server_modes,
        };

        let request = session_manager
            .build_request(namespaces)
            .context("failed to build device request")?;
        let session = SessionEstablishment {
            data: request.into(),
            e_reader_key: e_reader_key_public,
        };
        let session_request =
            cbor::to_vec(&session).context("failed to encode session establishment")?;

        Ok((session_manager, session_request, ble_ident))
    }

    #[deprecated(since = "0.2.1", note = "use ble_central_client_options instead")]
    pub fn first_central_client_uuid(&self) -> Option<&Uuid> {
        self.ble_central_client_options().next().map(|cc| &cc.uuid)
    }

    /// Retrieve the connection details for BLE central client mode offered by the mdoc, if any.
    ///
    /// The protocol allows for more than one central client mode to be offered, so a consumer
    /// of this API can use the first one that works.
    pub fn ble_central_client_options(&self) -> impl Iterator<Item = &CentralClientMode> {
        self.holder_central_client_modes.iter()
    }

    /// Retrieve the connection details for BLE peripheral server mode offered by the mdoc, if any.
    ///
    /// The protocol allows for more than one peripheral server mode to be offered, so a consumer
    /// of this API can use the first one that works.
    pub fn ble_peripheral_server_options(&self) -> impl Iterator<Item = &PeripheralServerMode> {
        self.holder_peripheral_server_modes.iter()
    }

    /// Retrieve the mdoc's preferred connection details.
    pub fn preferred_ble_mode(&self) -> Option<BleMode> {
        let first_central = self
            .holder_central_client_modes
            .first()
            .map(|m| BleMode::CentralClient(m.clone()));
        let first_peripheral = self
            .holder_peripheral_server_modes
            .first()
            .map(|m| BleMode::PeripheralServer(m.clone()));
        match self.holder_le_role {
            None | Some(LeRole::CentralPreferred) => first_central.or(first_peripheral),
            Some(LeRole::CentralOnly) => first_central,
            Some(LeRole::PeripheralOnly) => first_peripheral,
            Some(LeRole::PeripheralPreferred) => first_peripheral.or(first_central),
        }
    }

    /// Creates a new request with specified elements to request.
    pub fn new_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        let request = self.build_request(namespaces)?;
        let session = SessionData {
            data: Some(request.into()),
            status: None,
        };
        cbor::to_vec(&session).map_err(Into::into)
    }

    fn build_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        // if !validate_request(namespaces.clone()).is_ok() {
        //     return Err(anyhow::Error::msg(
        //         "At least one of the namespaces contain an invalid combination of fields to request",
        //     ));
        // }
        let items_request = ItemsRequest {
            doc_type: "org.iso.18013.5.1.mDL".into(),
            namespaces,
            request_info: None,
        };

        let doc_request = DocRequest {
            reader_auth: None,
            items_request: Tag24::new(items_request)?,
        };
        let device_request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(doc_request),
            device_request_info: None,
            reader_auth_all: None,
        };
        let device_request_bytes = cbor::to_vec(&device_request)?;
        session::encrypt_reader_data(
            &self.sk_reader.into(),
            &device_request_bytes,
            &mut self.reader_message_counter,
        )
        .map_err(|e| anyhow!("unable to encrypt request: {}", e))
    }

    fn decrypt_response(&mut self, response: &[u8]) -> Result<DeviceResponse, Error> {
        let session_data: SessionData = cbor::from_slice(response)?;
        let encrypted_response = match session_data.data {
            None => return Err(Error::HolderError),
            Some(r) => r,
        };
        let decrypted_response = session::decrypt_device_data(
            &self.sk_device.into(),
            encrypted_response.as_ref(),
            &mut self.device_message_counter,
        )
        .map_err(|_e| Error::DecryptionError)?;
        let device_response: DeviceResponse = cbor::from_slice(&decrypted_response)?;
        Ok(device_response)
    }

    /// Handle a device response, validating it and checking certificate revocation.
    ///
    /// # Arguments
    /// * `response` - The encrypted device response
    /// * `http_client` - HTTP client for CRL fetching. Use `&()` to skip CRL checks.
    pub async fn handle_response<C: CrlFetcher>(
        &mut self,
        response: &[u8],
        http_client: &C,
    ) -> ResponseAuthenticationOutcome {
        let mut validated_response = ResponseAuthenticationOutcome::default();

        let device_response = match self.decrypt_response(response) {
            Ok(device_response) => device_response,
            Err(e) => {
                validated_response
                    .errors
                    .insert("decryption_errors".to_string(), json!(vec![format!("{e}")]));
                return validated_response;
            }
        };

        match parse(&device_response) {
            Ok((document, x5chain, namespaces)) => {
                validate_response(
                    self.session_transcript.clone(),
                    self.trust_anchor_registry.clone(),
                    x5chain,
                    document.clone(),
                    namespaces,
                    http_client,
                )
                .await
            }
            Err(e) => {
                validated_response
                    .errors
                    .insert("parsing_errors".to_string(), json!(vec![format!("{e}")]));
                validated_response
            }
        }
    }
}

pub fn parse(
    device_response: &DeviceResponse,
) -> Result<(&Document, X5Chain, BTreeMap<String, Value>), Error> {
    let document = get_document(device_response)?;
    let header = document.issuer_signed.issuer_auth.unprotected.clone();
    let x5chain = header
        .rest
        .iter()
        .find(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
        .map(|(_, value)| value.to_owned())
        .map(X5Chain::from_cbor)
        .ok_or(Error::X5ChainMissing)?
        .map_err(Error::X5ChainParsing)?;
    let parsed_response = parse_namespaces(device_response)?;
    Ok((document, x5chain, parsed_response))
}

fn parse_response(value: ciborium::Value) -> Result<Value, Error> {
    match value {
        ciborium::Value::Text(s) => Ok(Value::String(s)),
        ciborium::Value::Tag(_t, v) => match *v {
            ciborium::Value::Text(d) => Ok(Value::String(d)),
            a => Err(Error::ParsingError(format!(
                "found {a:?} when expecting text"
            ))),
        },
        ciborium::Value::Array(v) => {
            let mut array_response = Vec::<Value>::new();
            for a in v {
                let r = parse_response(a)?;
                array_response.push(r);
            }
            Ok(json!(array_response))
        }
        ciborium::Value::Map(m) => {
            let mut map_response = serde_json::Map::<String, Value>::new();
            for (key, value) in m {
                if let ciborium::Value::Text(k) = key {
                    let parsed = parse_response(value)?;
                    map_response.insert(k, parsed);
                }
            }
            let json = json!(map_response);
            Ok(json)
        }
        ciborium::Value::Bytes(b) => Ok(json!(b)),
        ciborium::Value::Bool(b) => Ok(json!(b)),
        ciborium::Value::Integer(i) => Ok(json!(<ciborium::value::Integer as Into<i128>>::into(i))),
        a => Err(Error::ParsingError(format!(
            "found {a:?} when expecting anything but floats and nulls"
        ))),
    }
}

fn get_document(device_response: &DeviceResponse) -> Result<&Document, Error> {
    device_response
        .documents
        .as_ref()
        .ok_or(ReaderError::DeviceTransmissionError)?
        .iter()
        .find(|doc| doc.doc_type == "org.iso.18013.5.1.mDL")
        .ok_or(ReaderError::DocumentTypeError)
}

fn _validate_request(namespaces: device_request::Namespaces) -> Result<bool, Error> {
    // TODO: Check country name of certificate matches mdl

    // Check if request follows ISO18013-5 restrictions
    // A valid mdoc request can contain a maximum of 2 age_over_NN fields
    let age_over_nn_requested: Vec<(String, bool)> = namespaces
        .get("org.iso.18013.5.1")
        .map(|k| k.clone().into_inner())
        //To Do: get rid of unwrap
        .unwrap()
        .into_iter()
        .filter(|x| x.0.contains("age_over"))
        .collect();

    if age_over_nn_requested.len() > 2 {
        //To Do: Decide what should happen when more than two age_over_nn are requested
        return Err(Error::InvalidRequest);
    }

    Ok(true)
}

// TODO: Support other namespaces.
pub fn parse_namespaces(
    device_response: &DeviceResponse,
) -> Result<BTreeMap<String, serde_json::Value>, Error> {
    let mut core_namespace = BTreeMap::<String, serde_json::Value>::new();
    let mut aamva_namespace = BTreeMap::<String, serde_json::Value>::new();
    let mut parsed_response = BTreeMap::<String, serde_json::Value>::new();
    let mut namespaces = device_response
        .documents
        .as_ref()
        .ok_or(Error::DeviceTransmissionError)?
        .iter()
        .find(|doc| doc.doc_type == "org.iso.18013.5.1.mDL")
        .ok_or(Error::DocumentTypeError)?
        .issuer_signed
        .namespaces
        .as_ref()
        .ok_or(Error::NoMdlDataTransmission)?
        .clone()
        .into_inner();

    namespaces
        .remove("org.iso.18013.5.1")
        .ok_or(Error::IncorrectNamespace)?
        .into_inner()
        .into_iter()
        .map(|item| item.into_inner())
        .for_each(|item| {
            let value = parse_response(item.element_value.clone());
            if let Ok(val) = value {
                core_namespace.insert(item.element_identifier, val);
            }
        });

    parsed_response.insert(
        "org.iso.18013.5.1".to_string(),
        serde_json::to_value(core_namespace)?,
    );

    if let Some(aamva_response) = namespaces.remove("org.iso.18013.5.1.aamva") {
        aamva_response
            .into_inner()
            .into_iter()
            .map(|item| item.into_inner())
            .for_each(|item| {
                let value = parse_response(item.element_value.clone());
                if let Ok(val) = value {
                    aamva_namespace.insert(item.element_identifier, val);
                }
            });

        parsed_response.insert(
            "org.iso.18013.5.1.aamva".to_string(),
            serde_json::to_value(aamva_namespace)?,
        );
    }
    Ok(parsed_response)
}

#[cfg(test)]
pub mod test {
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
}
