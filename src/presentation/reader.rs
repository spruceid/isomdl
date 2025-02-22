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

use anyhow::Context;
use anyhow::{anyhow, Result};
use coset::Label;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use uuid::Uuid;

use super::authentication::{
    mdoc::{device_authentication, issuer_authentication},
    AuthenticationStatus, ResponseAuthenticationOutcome,
};

use crate::definitions::x509;
use crate::{
    cbor::{self, CborError},
    definitions::{
        device_engagement::DeviceRetrievalMethod,
        device_key::cose_key::Error as CoseError,
        device_request::{self, DeviceRequest, DocRequest, ItemsRequest},
        device_response::Document,
        helpers::{non_empty_vec, NonEmptyVec, Tag24},
        session::{
            self, create_p256_ephemeral_keys, derive_session_key, get_shared_secret, Handover,
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
}

#[derive(Serialize, Deserialize)]
pub struct ReaderAuthentication(
    pub String,
    pub SessionTranscript180135,
    pub ItemsRequestBytes,
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
    #[error("Unexpected data type for data element.")]
    ParsingError,
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

impl SessionManager {
    /// Establish a session with the device.
    ///
    /// Internally it generates the ephemeral keys,
    /// derives the shared secret, and derives the session keys
    /// (using **Diffie–Hellman key exchange**).
    pub fn establish_session(
        qr_code: String,
        namespaces: device_request::Namespaces,
        trust_anchor_registry: TrustAnchorRegistry,
    ) -> Result<(Self, Vec<u8>, [u8; 16])> {
        let device_engagement_bytes = Tag24::<DeviceEngagement>::from_qr_code_uri(&qr_code)
            .context("failed to construct QR code")?;

        Self::establish_session_with_handover(
            device_engagement_bytes,
            namespaces,
            trust_anchor_registry,
            Handover::QR,
        )
    }

    /// Establish a session with the device, using the specified handover type.
    ///
    /// Internally it generates the ephemeral keys,
    /// derives the shared secret, and derives the session keys
    /// (using **Diffie–Hellman key exchange**).
    pub fn establish_session_with_handover(
        device_engagement_bytes: Tag24<DeviceEngagement>,
        namespaces: device_request::Namespaces,
        trust_anchor_registry: TrustAnchorRegistry,
        handover: Handover,
    ) -> Result<(Self, Vec<u8>, [u8; 16])> {
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
            handover,
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

    pub fn first_central_client_uuid(&self) -> Option<&Uuid> {
        self.session_transcript
            .0
            .as_ref()
            .device_retrieval_methods
            .as_ref()
            .and_then(|ms| {
                ms.as_ref()
                    .iter()
                    .filter_map(|m| match m {
                        DeviceRetrievalMethod::BLE(opt) => {
                            opt.central_client_mode.as_ref().map(|cc| &cc.uuid)
                        }
                        _ => None,
                    })
                    .next()
            })
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

    pub fn handle_response(&mut self, response: &[u8]) -> ResponseAuthenticationOutcome {
        let mut validated_response = ResponseAuthenticationOutcome::default();

        let device_response = match self.decrypt_response(response) {
            Ok(device_response) => device_response,
            Err(e) => {
                validated_response.errors.insert(
                    "decryption_errors".to_string(),
                    json!(vec![format!("{e:?}")]),
                );
                return validated_response;
            }
        };

        match parse(&device_response) {
            Ok((document, x5chain, namespaces)) => {
                self.validate_response(x5chain, document.clone(), namespaces)
            }
            Err(e) => {
                validated_response
                    .errors
                    .insert("parsing_errors".to_string(), json!(vec![format!("{e:?}")]));
                validated_response
            }
        }
    }

    fn validate_response(
        &mut self,
        x5chain: X5Chain,
        document: Document,
        namespaces: BTreeMap<String, serde_json::Value>,
    ) -> ResponseAuthenticationOutcome {
        let mut validated_response = ResponseAuthenticationOutcome {
            response: namespaces,
            ..Default::default()
        };

        match device_authentication(&document, self.session_transcript.clone()) {
            Ok(_) => {
                validated_response.device_authentication = AuthenticationStatus::Valid;
            }
            Err(e) => {
                validated_response.device_authentication = AuthenticationStatus::Invalid;
                validated_response.errors.insert(
                    "device_authentication_errors".to_string(),
                    json!(vec![format!("{e:?}")]),
                );
            }
        }

        let validation_errors = x509::validation::ValidationRuleset::Mdl
            .validate(&x5chain, &self.trust_anchor_registry)
            .errors;
        if validation_errors.is_empty() {
            match issuer_authentication(x5chain, &document.issuer_signed) {
                Ok(_) => {
                    validated_response.issuer_authentication = AuthenticationStatus::Valid;
                }
                Err(e) => {
                    validated_response.issuer_authentication = AuthenticationStatus::Invalid;
                    validated_response.errors.insert(
                        "issuer_authentication_errors".to_string(),
                        serde_json::json!(vec![format!("{e:?}")]),
                    );
                }
            }
        } else {
            validated_response
                .errors
                .insert("certificate_errors".to_string(), json!(validation_errors));
            validated_response.issuer_authentication = AuthenticationStatus::Invalid
        };

        validated_response
    }
}

fn parse(
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
        ciborium::Value::Tag(_t, v) => {
            if let ciborium::Value::Text(d) = *v {
                Ok(Value::String(d))
            } else {
                Err(Error::ParsingError)
            }
        }
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
        _ => Err(Error::ParsingError),
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
fn parse_namespaces(
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
