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
use std::collections::BTreeSet;

use crate::definitions::x509::validation::ProfileSelector;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::{
    authentication::{ResponseError, ResponseValidationOutcome},
    reader_utils::{validate_response, ReaderValidationConfig},
};

use crate::definitions::x509::revocation::RevocationFetcher;
pub use crate::definitions::x509::validation::ValidationOptions;

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
        helpers::{non_empty_vec, NonEmptyVec, Tag24},
        session::{
            self, create_p256_ephemeral_keys, derive_session_key, get_shared_secret,
            SessionEstablishment,
        },
        x509::trust_anchor::TrustAnchorRegistry,
        DeviceEngagement, DeviceResponse, SessionData, SessionTranscript180135,
    },
    presentation::reader::device_request::ItemsRequestBytes,
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
    e_reader_key_private: [u8; 32],
    trust_anchor_registry: TrustAnchorRegistry,
    holder_le_role: Option<LeRole>,
    holder_central_client_modes: Vec<CentralClientMode>,
    holder_peripheral_server_modes: Vec<PeripheralServerMode>,
    /// Every doc type this session has ever asked for.
    ///
    /// Maintained by [`SessionManager::build_request`] and never settable from outside:
    /// a caller-supplied value could silently widen what the reader accepts.
    ///
    /// `#[serde(default)]` is **mandatory**. Consumers persist this struct across
    /// deploys — without it, every session in flight when the new version ships would
    /// fail to deserialize. A session restored from such state has `None` here, which
    /// disables the filter and raises
    /// [`ResponseWarning::RequestedDocTypesUnknown`](super::authentication::ResponseWarning::RequestedDocTypesUnknown).
    #[serde(default)]
    requested_doc_types: Option<BTreeSet<String>>,
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
    /// Unexpected CBOR type for offered value.
    #[error("Unexpected CBOR type for offered value")]
    CborDecodingError,
    /// Not a valid JSON input.
    #[error("not a valid JSON input.")]
    JsonError,
    /// Unexpected data type for data element.
    #[error("Unexpected data type for data element: {0}.")]
    ParsingError(String),
    #[error("Failed mdoc authentication: {0}")]
    MdocAuth(String),
    #[error("Currently unsupported format")]
    Unsupported,
    #[error("issuer authentication failed: {0}")]
    IssuerAuthentication(String),
    #[error("Unable to parse issuer public key")]
    IssuerPublicKey(anyhow::Error),
    /// A disclosed data element does not match the digest committed to in the MSO.
    #[error("issuer-signed value digest verification failed: {0}")]
    IssuerDigestMismatch(String),
    /// The MSO's `validUntil` is in the past relative to the validation time.
    #[error("MSO is expired")]
    MsoExpired,
    /// The MSO's `validFrom` is in the future relative to the validation time.
    #[error("MSO is not yet valid")]
    MsoNotYetValid,
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
    ///
    /// `items_requests` names one or more credentials to ask for, each with its own doc
    /// type and namespaces. Use [`ItemsRequest::mdl`] for the common single-mDL case.
    pub fn establish_session(
        handover: Handover,
        items_requests: NonEmptyVec<ItemsRequest>,
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
                let device_engagement_bytes = carrier_info.device_engagement;
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

        // Save private key bytes before consuming the key for ECDH
        let e_reader_key_private_bytes: [u8; 32] = e_reader_key_private.to_bytes().into();

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

        tracing::debug!(
            "reader SessionTranscript ({} bytes): {:?}",
            session_transcript_bytes.inner_bytes.len(),
            session_transcript_bytes.inner_bytes.as_slice()
        );

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
            e_reader_key_private: e_reader_key_private_bytes,
            trust_anchor_registry,
            holder_le_role,
            holder_central_client_modes,
            holder_peripheral_server_modes,
            requested_doc_types: Some(BTreeSet::new()),
        };

        let request = session_manager
            .build_request(items_requests)
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

    /// Creates a new request for the given credentials.
    ///
    /// Callable more than once in a session. Every doc type asked for, in this call or
    /// an earlier one, stays in the set the response is filtered against — the holder
    /// may legitimately answer an earlier request.
    pub fn new_request(&mut self, items_requests: NonEmptyVec<ItemsRequest>) -> Result<Vec<u8>> {
        let request = self.build_request(items_requests)?;
        let session = SessionData {
            data: Some(request.into()),
            status: None,
        };
        cbor::to_vec(&session).map_err(Into::into)
    }

    /// The doc types this session has asked for.
    ///
    /// `None` only for a session deserialized from state written before this field
    /// existed; see the note on the field itself.
    pub fn requested_doc_types(&self) -> Option<&BTreeSet<String>> {
        self.requested_doc_types.as_ref()
    }

    fn build_request(&mut self, items_requests: NonEmptyVec<ItemsRequest>) -> Result<Vec<u8>> {
        // Union rather than replace: a holder answering an earlier request is not
        // sending an unsolicited credential.
        let asked = self.requested_doc_types.get_or_insert_with(BTreeSet::new);
        for items_request in items_requests.iter() {
            asked.insert(items_request.doc_type.clone());
        }

        let doc_requests = items_requests
            .into_inner()
            .into_iter()
            .map(|items_request| {
                Ok(DocRequest {
                    reader_auth: None,
                    items_request: Tag24::new(items_request)?,
                })
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            // `items_requests` was non-empty, so this cannot fail.
            .map_err(|e| anyhow!("could not build doc requests: {e}"))?;

        let device_request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests,
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

    fn decrypt_response(&mut self, response: &[u8]) -> Result<DeviceResponse, ResponseError> {
        let session_data: SessionData =
            cbor::from_slice(response).map_err(|e| ResponseError::CborDecoding {
                detail: format!("could not decode the session data: {e}"),
            })?;
        tracing::debug!(
            "decrypt_response: {} response bytes, data_present={}, status={:?}",
            response.len(),
            session_data.data.is_some(),
            session_data.status.as_ref()
        );
        let encrypted_response = match session_data.data {
            // The holder ended the session rather than answering. There is no response
            // to validate, and the session status is the only thing it told us.
            None => {
                return Err(ResponseError::Other {
                    code: "holder_error".to_string(),
                    detail: match session_data.status {
                        Some(status) => format!(
                            "the holder returned session status {status:?} instead of a response"
                        ),
                        None => "the holder returned neither data nor a session status".to_string(),
                    },
                })
            }
            Some(r) => r,
        };
        let decrypted_response = session::decrypt_device_data(
            &self.sk_device.into(),
            encrypted_response.as_ref(),
            &mut self.device_message_counter,
        )
        .map_err(|_e| ResponseError::Decryption {
            detail: "session decryption failed".to_string(),
        })?;
        tracing::debug!(
            "decrypt_response: decrypted OK, {} plaintext bytes (from {} encrypted)",
            decrypted_response.len(),
            encrypted_response.as_ref().len()
        );
        cbor::from_slice(&decrypted_response).map_err(|e| ResponseError::CborDecoding {
            detail: format!("could not decode the device response: {e}"),
        })
    }

    /// Handle a device response, validating it and checking certificate revocation.
    ///
    /// Validity checks (certificate windows and the MSO `validityInfo` window) are
    /// performed against the current time. Use [`Self::handle_response_with_options`]
    /// to pin the validation time.
    ///
    /// # Arguments
    /// * `response` - The encrypted device response
    /// * `revocation_fetcher` - Revocation fetcher for CRL checking. Use `&()` to skip revocation checks.
    pub async fn handle_response<P: ProfileSelector, R: RevocationFetcher>(
        &mut self,
        response: &[u8],
        profiles: &P,
        revocation_fetcher: &R,
    ) -> ResponseValidationOutcome {
        self.handle_response_with_options(
            response,
            profiles,
            revocation_fetcher,
            &ValidationOptions::default(),
        )
        .await
    }

    /// Like [`Self::handle_response`], but with explicit [`ValidationOptions`].
    ///
    /// The `options` control the validation time used both for certificate chain
    /// validity checks and for the MSO `validityInfo` window check.
    pub async fn handle_response_with_options<P: ProfileSelector, R: RevocationFetcher>(
        &mut self,
        response: &[u8],
        profiles: &P,
        revocation_fetcher: &R,
        options: &ValidationOptions,
    ) -> ResponseValidationOutcome {
        let device_response = match self.decrypt_response(response) {
            Ok(device_response) => device_response,
            Err(e) => {
                return ResponseValidationOutcome {
                    documents: Vec::new(),
                    failed: Vec::new(),
                    rejected: Vec::new(),
                    errors: vec![e],
                    status: None,
                    document_errors: Vec::new(),
                    warnings: Vec::new(),
                };
            }
        };

        let config = ReaderValidationConfig {
            trust_anchors: &self.trust_anchor_registry,
            requested_doc_types: self.requested_doc_types.as_ref(),
            options,
            profiles,
        };

        validate_response(
            &device_response,
            &self.session_transcript,
            &config,
            revocation_fetcher,
            &self.e_reader_key_private,
        )
        .await
    }
}

/// Convert a CBOR data element value into JSON.
///
/// Refuses only what has no JSON representation (floats, non-text map keys), and
/// reports that refusal rather than dropping the value.
pub(crate) fn parse_response(value: ciborium::Value) -> Result<Value, Error> {
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

#[cfg(test)]
#[path = "tests/reader.rs"]
pub mod test;
