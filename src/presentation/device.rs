//! This module is responsible for establishing the device's session with the reader.
//!
//! The device's [SessionManager] state machine is responsible
//! for handling the session with the reader.
//!
//! The session is managed through a set of session management states: initialization, engaged,
//! and established.
//!
//! To initialize a session management state, see the [SessionManagerInit] struct.
//!
//! ```ignore
#![doc = include_str!("../../docs/on_simulated_device.txt")]
//! ```
//!
//! ### Example
//!
//! You can view examples in `tests` directory in `simulated_device_and_reader.rs`, for a basic example and
//! `simulated_device_and_reader_state.rs` which uses `State` pattern, `Arc` and `Mutex`.
use crate::{
    cbor,
    cose::{mac0::PreparedCoseMac0, sign1::PreparedCoseSign1, MaybeTagged},
    definitions::{
        device_engagement::{DeviceRetrievalMethod, Security, ServerRetrievalMethods},
        device_request::{DeviceRequest, DocRequest, ItemsRequest},
        device_response::{
            Document as DeviceResponseDoc, DocumentError, DocumentErrorCode, DocumentErrors,
            Errors as NamespaceErrors, Status,
        },
        device_signed::{
            DeviceAuth, DeviceAuthType, DeviceAuthentication, DeviceNamespacesBytes, DeviceSigned,
        },
        helpers::{tag24, NonEmptyMap, NonEmptyVec, Tag24},
        issuer_signed::{IssuerSigned, IssuerSignedItemBytes},
        session::{
            self, derive_session_key, get_shared_secret, Handover, SessionData, SessionTranscript,
        },
        x509::{
            self, trust_anchor::TrustAnchorRegistry, x5chain::X5CHAIN_COSE_HEADER_LABEL, X5Chain,
        },
        CoseKey, DeviceEngagement, DeviceResponse, IssuerSignedItem, Mso, SessionEstablishment,
    },
    issuance::Mdoc,
};
use coset::Label;
use coset::{CoseMac0Builder, CoseSign1, CoseSign1Builder};
use ecdsa::VerifyingKey;
use p256::{FieldBytes, NistP256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use session::SessionTranscript180135;
use std::collections::BTreeMap;
use std::num::ParseIntError;
use uuid::Uuid;

use super::{
    authentication::{AuthenticationStatus, RequestAuthenticationOutcome},
    reader::ReaderAuthentication,
};

/// Initialisation state.
///
/// You enter this state using [SessionManagerInit::initialise] method, providing
/// the documents and optional non-empty list of device [DeviceRetrievalMethod] and
/// server [ServerRetrievalMethods] retrieval methods.
///
/// The [SessionManagerInit] state is restricted to creating a QR-code engagement,
/// using the [SessionManagerInit::qr_engagement] method, which will return the
/// [SessionManagerEngaged] Session Manager state.
///
/// For convenience, the [SessionManagerInit] state surfaces the [SessionManagerInit::ble_ident] method
/// to provide the BLE identification string for the device.
#[derive(Serialize, Deserialize)]
pub struct SessionManagerInit {
    documents: Documents,
    e_device_key: Vec<u8>,
    device_engagement: Tag24<DeviceEngagement>,
}

/// Engaged state.
///
/// Transition to this state is made with [SessionManagerInit::qr_engagement].
/// That creates the `QR code` that the reader will use to establish the session.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionManagerEngaged {
    documents: Documents,
    e_device_key: Vec<u8>,
    device_engagement: Tag24<DeviceEngagement>,
    handover: Handover,
}

/// The initial state of the Session Manager.
///
/// The Session Manager contains the documents, ephemeral device key, and device engagement.
///
/// Create a new Session Manager using the [SessionManagerInit::initialise] method, providing
/// the documents and optional non-empty list of device [DeviceRetrievalMethod] and
/// server [ServerRetrievalMethods] retrieval methods.
///
/// The [SessionManagerInit] state is restricted to creating a QR-code engagement,
/// using the [SessionManagerInit::qr_engagement] method, which will return the
/// [SessionManagerEngaged] Session Manager state.
///
/// For convience, the [SessionManagerInit] state surfaces the [SessionManagerInit::ble_ident] method
/// to provide the BLE identification string for the device.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionManager {
    documents: Documents,
    session_transcript: SessionTranscript180135,
    sk_device: [u8; 32],
    device_message_counter: u32,
    sk_reader: [u8; 32],
    reader_message_counter: u32,
    state: State,
    trusted_verifiers: TrustAnchorRegistry,
    device_auth_type: DeviceAuthType,
}

/// The internal states of the [SessionManager].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum State {
    /// This is the default one where the device is waiting for a request from the reader.
    #[default]
    AwaitingRequest,
    /// The device is signing the response. The response could be a document or an error.
    Signing(PreparedDeviceResponse),
    /// The device is ready to respond to the reader with a signed response.
    ReadyToRespond(Vec<u8>),
}

/// Various errors that can occur during the interaction with the reader.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Unable to generate ephemeral key.
    #[error("unable to generate ephemeral key: {0}")]
    EKeyGeneration(session::Error),
    /// Error encoding value to CBOR.
    #[error("error encoding value to CBOR: {0}")]
    Tag24CborEncoding(tag24::Error),
    /// Unable to generate shared secret.
    #[error("unable to generate shared secret: {0}")]
    SharedSecretGeneration(anyhow::Error),
    /// Error encoding value to CBOR.
    #[error("error encoding value to CBOR: {0}")]
    CborEncoding(coset::CoseError),
    /// Session manager was used incorrectly.
    #[error("session manager was used incorrectly")]
    ApiMisuse,
    /// Could not parse age attestation claim.
    #[error("could not parse age attestation claim")]
    ParsingError(#[from] ParseIntError),
    /// `age_over` element identifier is malformed.
    #[error("age_over element identifier is malformed")]
    PrefixError,
    #[error("error decoding reader authentication certificate")]
    CertificateError,
    #[error("error while validating reader authentication certificate")]
    ValidationError,
    #[error("Could not serialize to cbor: {0}")]
    CborError(coset::CoseError),
}

impl From<x509_cert::der::Error> for Error {
    fn from(_value: x509_cert::der::Error) -> Self {
        Error::CertificateError
    }
}

/// The documents the device owns.
pub type Documents = NonEmptyMap<DocType, Document>;
type DocType = String;

/// Device-internal document datatype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: Uuid,
    pub issuer_auth: MaybeTagged<CoseSign1>,
    pub mso: Mso,
    pub namespaces: Namespaces,
}

/// Stores the prepared response.
///
/// After the device parses the request from the reader,
/// If there were errors,
/// it will prepare a list of [DocumentErrors].
/// If there are documents to be signed,
/// it will keep a list of prepared documents
/// which needs to be signed with [SessionManager::get_next_signature_payload] and [SessionManager::submit_next_signature].
/// After those are signed, they are kept in a list of [DeviceResponseDoc]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedDeviceResponse {
    pub prepared_documents: Vec<PreparedDocument>,
    pub signed_documents: Vec<DeviceResponseDoc>,
    pub document_errors: Option<DocumentErrors>,
    pub status: Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedDocument {
    pub id: Uuid,
    pub doc_type: String,
    pub issuer_signed: IssuerSigned,
    pub device_namespaces: DeviceNamespacesBytes,
    pub prepared_cose: PreparedCose,
    pub errors: Option<NamespaceErrors>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReaderAuthOutcome {
    pub common_name: Option<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreparedCose {
    Sign1(PreparedCoseSign1),
    Mac0(PreparedCoseMac0),
}

impl PreparedCose {
    fn signature_payload(&self) -> &[u8] {
        match self {
            PreparedCose::Sign1(inner) => inner.signature_payload(),
            PreparedCose::Mac0(inner) => inner.signature_payload(),
        }
    }
}

/// Elements in a namespace.
type Namespaces = NonEmptyMap<Namespace, NonEmptyMap<ElementIdentifier, IssuerSignedItemBytes>>;
type Namespace = String;
type ElementIdentifier = String;

/// A list of the requested items by the reader.
pub type RequestedItems = Vec<ItemsRequest>;
/// The lis of items that are permitted to be shared grouped by document type and namespace.
pub type PermittedItems = BTreeMap<DocType, BTreeMap<Namespace, Vec<ElementIdentifier>>>;

impl SessionManagerInit {
    /// Initialise the SessionManager.
    ///
    /// This is the first transition in the flow interaction.
    /// Internally, it generates the ephemeral key and creates the device engagement.
    ///
    /// It transition to [SessionManagerInit] state.
    pub fn initialise(
        documents: Documents,
        device_retrieval_methods: Option<NonEmptyVec<DeviceRetrievalMethod>>,
        server_retrieval_methods: Option<ServerRetrievalMethods>,
    ) -> Result<Self, Error> {
        let (e_device_key, e_device_key_pub) =
            session::create_p256_ephemeral_keys().map_err(Error::EKeyGeneration)?;
        let e_device_key_bytes =
            Tag24::<CoseKey>::new(e_device_key_pub).map_err(Error::Tag24CborEncoding)?;
        let security = Security(1, e_device_key_bytes);

        let device_engagement = DeviceEngagement {
            version: "1.0".to_string(),
            security,
            device_retrieval_methods,
            server_retrieval_methods,
            protocol_info: None,
        };

        let device_engagement =
            Tag24::<DeviceEngagement>::new(device_engagement).map_err(Error::Tag24CborEncoding)?;

        Ok(Self {
            documents,
            e_device_key: e_device_key.to_bytes().to_vec(),
            device_engagement,
        })
    }

    pub fn ble_ident(&self) -> anyhow::Result<[u8; 16]> {
        super::calculate_ble_ident(&self.device_engagement.as_ref().security.1)
    }

    /// Begins the device engagement using **QR code**.
    ///
    /// The response contains the device's public key and engagement data.
    pub fn qr_engagement(self) -> anyhow::Result<(SessionManagerEngaged, String)> {
        let qr_code_uri = self.device_engagement.to_qr_code_uri()?;
        let sm = SessionManagerEngaged {
            documents: self.documents,
            device_engagement: self.device_engagement,
            e_device_key: self.e_device_key,
            handover: Handover::QR,
        };
        Ok((sm, qr_code_uri))
    }
}

impl SessionManagerEngaged {
    /// It transitions to [SessionManager] state
    /// by processing the [SessionEstablishment] received from the reader.
    ///
    /// Internally, it generates the session keys based on the calculated shared secret
    /// (using **Diffie–Hellman key exchange**).
    ///
    /// Along with transitioning to [SessionManagerEngaged] state,
    /// it returns the requested items by the reader.
    pub fn process_session_establishment(
        self,
        session_establishment: SessionEstablishment,
        trusted_verifiers: TrustAnchorRegistry,
    ) -> anyhow::Result<(SessionManager, RequestAuthenticationOutcome)> {
        let e_reader_key = session_establishment.e_reader_key;
        let session_transcript =
            SessionTranscript180135(self.device_engagement, e_reader_key.clone(), self.handover);
        let session_transcript_bytes =
            Tag24::new(session_transcript.clone()).map_err(Error::Tag24CborEncoding)?;

        let e_device_key = p256::SecretKey::from_bytes(FieldBytes::from_slice(&self.e_device_key))?;

        let shared_secret = get_shared_secret(e_reader_key.into_inner(), &e_device_key.into())
            .map_err(Error::SharedSecretGeneration)?;

        let sk_reader = derive_session_key(&shared_secret, &session_transcript_bytes, true)?.into();
        let sk_device =
            derive_session_key(&shared_secret, &session_transcript_bytes, false)?.into();

        let mut sm = SessionManager {
            documents: self.documents,
            session_transcript,
            sk_device,
            device_message_counter: 0,
            sk_reader,
            reader_message_counter: 0,
            state: State::AwaitingRequest,
            trusted_verifiers,
            device_auth_type: DeviceAuthType::Sign1,
        };

        let validated_request = sm.handle_decoded_request(SessionData {
            data: Some(session_establishment.data),
            status: None,
        });

        Ok((sm, validated_request))
    }
}

impl SessionManager {
    fn parse_request(&self, request: &[u8]) -> Result<DeviceRequest, PreparedDeviceResponse> {
        let request: ciborium::Value = cbor::from_slice(request).map_err(|error| {
            tracing::error!("unable to decode DeviceRequest bytes as cbor: {}", error);
            PreparedDeviceResponse::empty(Status::CborDecodingError)
        })?;

        cbor::from_value(request).map_err(|error| {
            tracing::error!("unable to validate DeviceRequest cbor: {}", error);
            PreparedDeviceResponse::empty(Status::CborValidationError)
        })
    }

    fn validate_request(&self, request: DeviceRequest) -> RequestAuthenticationOutcome {
        let items_request: Vec<ItemsRequest> = request
            .doc_requests
            .clone()
            .into_inner()
            .into_iter()
            .map(|DocRequest { items_request, .. }| items_request.into_inner())
            .collect();

        let mut validated_request = RequestAuthenticationOutcome {
            items_request,
            common_name: None,
            reader_authentication: AuthenticationStatus::Unchecked,
            errors: BTreeMap::new(),
        };

        if request.version != DeviceRequest::VERSION {
            tracing::error!(
                "unsupported DeviceRequest version: {} ({} is supported)",
                request.version,
                DeviceRequest::VERSION
            );
            validated_request.errors.insert(
                "parsing_errors".to_string(),
                json!(vec!["unsupported DeviceRequest version".to_string()]),
            );
        }
        if let Some(doc_request) = request.doc_requests.first() {
            let outcome = self.reader_authentication(doc_request.clone());
            if outcome.errors.is_empty() {
                validated_request.reader_authentication = AuthenticationStatus::Valid;
            } else {
                validated_request.reader_authentication = AuthenticationStatus::Invalid;
                tracing::error!("Reader authentication errors: {:#?}", outcome.errors);
            }

            validated_request.common_name = outcome.common_name;
        }

        validated_request
    }

    /// When the device is ready to respond, it prepares the response specifying the permitted items.
    ///
    /// It changes the internal state to [State::Signing],
    /// and you need
    /// to call [SessionManager::get_next_signature_payload] and then [SessionManager::submit_next_signature]
    /// to sign the documents.
    ///
    /// # Example
    ///
    /// ```text
    /// session_manager.prepare_response(&requested_items, permitted_items);
    /// let (_, payload)) = session_manager.get_next_signature_payload()?;
    /// let signature = sign(&payload);
    /// session_manager.submit_next_signature(signature);
    /// ```
    pub fn prepare_response(&mut self, requests: &RequestedItems, permitted: PermittedItems) {
        let prepared_response = DeviceSession::prepare_response(self, requests, permitted);
        self.state = State::Signing(prepared_response);
    }

    fn handle_decoded_request(&mut self, request: SessionData) -> RequestAuthenticationOutcome {
        let mut validated_request = RequestAuthenticationOutcome::default();
        let data = match request.data {
            Some(d) => d,
            None => {
                validated_request.errors.insert(
                    "parsing_errors".to_string(),
                    json!(vec![
                        "no mdoc requests received, assume session can be terminated".to_string()
                    ]),
                );
                return validated_request;
            }
        };
        let decrypted_request = match session::decrypt_reader_data(
            &self.sk_reader.into(),
            data.as_ref(),
            &mut self.reader_message_counter,
        )
        .map_err(|e| anyhow::anyhow!("unable to decrypt request: {}", e))
        {
            Ok(decrypted) => decrypted,
            Err(e) => {
                validated_request
                    .errors
                    .insert("decryption_errors".to_string(), json!(vec![e.to_string()]));
                return validated_request;
            }
        };

        let request = match self.parse_request(&decrypted_request) {
            Ok(r) => r,
            Err(e) => {
                self.state = State::Signing(e);
                return RequestAuthenticationOutcome::default();
            }
        };

        self.validate_request(request)
    }

    /// Handle a request from the reader.
    ///
    /// The request is expected to be a CBOR encoded
    /// and encrypted [SessionData].
    ///
    /// This method will return the [RequestAuthenticationOutcome] struct, which will
    /// include the items requested by the reader/verifier.
    pub fn handle_request(&mut self, request: &[u8]) -> RequestAuthenticationOutcome {
        let mut validated_request = RequestAuthenticationOutcome::default();
        let session_data: SessionData = match cbor::from_slice(request) {
            Ok(sd) => sd,
            Err(e) => {
                validated_request
                    .errors
                    .insert("parsing_errors".to_string(), json!(vec![e.to_string()]));
                return validated_request;
            }
        };
        self.handle_decoded_request(session_data)
    }

    /// When there are documents to be signed, it will return then next one for signing.
    ///
    /// After signed, you need to call [SessionManager::submit_next_signature].
    ///
    /// # Example
    ///
    /// ```ignore
    /// while let Some((_, payload)) = session_manager.get_next_signature_payload()? {
    ///     let signature = sign(&payload);
    ///     session_manager.submit_next_signature(signature);
    /// }
    /// ```
    pub fn get_next_signature_payload(&self) -> Option<(Uuid, &[u8])> {
        match &self.state {
            State::Signing(p) => p.get_next_signature_payload(),
            _ => None,
        }
    }

    /// Submit the externally signed signature for object
    /// returned by [SessionManager::get_next_signature_payload].
    ///
    /// After all documents are signed, you can call [SessionManager::retrieve_response]
    /// to get the response that can then be sent to the reader.
    ///
    /// # Example
    ///
    /// ```ignore
    /// while let Some((_, payload)) = session_manager.get_next_signature_payload()? {
    ///     let signature = sign(&payload);
    ///     session_manager.submit_next_signature(signature);
    /// }
    /// ```
    pub fn submit_next_signature(&mut self, signature: Vec<u8>) -> anyhow::Result<()> {
        if matches!(self.state, State::Signing(_)) {
            match std::mem::take(&mut self.state) {
                State::Signing(mut p) => {
                    p.submit_next_signature(signature);
                    if p.is_complete() {
                        let response = p.finalize_response();
                        let bytes = cbor::to_vec(&response)?;
                        let response2: DeviceResponse = cbor::from_slice(&bytes).unwrap();
                        let bytes2 = cbor::to_vec(&response2)?;
                        assert_eq!(bytes, bytes2);
                        let mut status: Option<session::Status> = None;
                        let response_bytes = cbor::to_vec(&response)?;
                        let encrypted_response = session::encrypt_device_data(
                            &self.sk_device.into(),
                            &response_bytes,
                            &mut self.device_message_counter,
                        )
                        .unwrap_or_else(|_e| {
                            //tracing::warn!("unable to encrypt response: {}", e);
                            status = Some(session::Status::SessionEncryptionError);
                            Default::default()
                        });
                        let data = if status.is_some() {
                            None
                        } else {
                            Some(encrypted_response.into())
                        };
                        let session_data = SessionData { status, data };
                        let encoded_response = crate::cbor::to_vec(&session_data)?;
                        self.state = State::ReadyToRespond(encoded_response);
                    } else {
                        self.state = State::Signing(p)
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    /// Identifies if the response is ready.
    ///
    /// The internal state is [State::ReadyToRespond] in this returns `true`.
    pub fn response_ready(&self) -> bool {
        matches!(self.state, State::ReadyToRespond(_))
    }

    /// Retrieves the prepared response.
    ///
    /// Will return [Some] after all documents have been signed.
    /// In that case, it will return the response
    /// and change the internal state to [State::AwaitingRequest]
    /// where it can accept new a request from the reader.
    pub fn retrieve_response(&mut self) -> Option<Vec<u8>> {
        if self.response_ready() {
            // Replace state with AwaitingRequest.
            let state = std::mem::take(&mut self.state);
            match state {
                State::ReadyToRespond(r) => Some(r),
                // Unreachable as the state variant has already been checked.
                _ => unreachable!(),
            }
        } else {
            None
        }
    }

    pub fn reader_authentication(&self, doc_request: DocRequest) -> ReaderAuthOutcome {
        let mut outcome = ReaderAuthOutcome::default();

        let Some(reader_auth) = doc_request.reader_auth else {
            outcome
                .errors
                .push("Processing: request does not contain reader auth".into());
            return outcome;
        };

        let Some(x5chain_cbor) = reader_auth
            .unprotected
            .rest
            .iter()
            .find(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
            .map(|(_, value)| value)
        else {
            outcome
                .errors
                .push("Processing: reader auth does not contain x5chain".into());
            return outcome;
        };

        let x5chain = match X5Chain::from_cbor(x5chain_cbor.clone()) {
            Ok(x5c) => x5c,
            Err(e) => {
                outcome
                    .errors
                    .push(format!("Processing: x5chain cannot be decoded: {e}"));
                return outcome;
            }
        };

        outcome.common_name = Some(x5chain.end_entity_common_name().to_string());

        let x5chain_validation_outcome = x509::validation::ValidationRuleset::MdlReaderOneStep
            .validate(&x5chain, &self.trusted_verifiers);

        outcome.errors.extend(x5chain_validation_outcome.errors);

        // TODO: Support more than P-256.
        let verifier: VerifyingKey<NistP256> = match x5chain.end_entity_public_key() {
            Ok(verifier) => verifier,
            Err(e) => {
                outcome.errors.push(format!(
                    "Processing: reader public key cannot be decoded: {e}"
                ));
                return outcome;
            }
        };

        let detached_payload = match Tag24::new(ReaderAuthentication(
            "ReaderAuthentication".into(),
            self.session_transcript.clone(),
            doc_request.items_request,
        )) {
            Ok(tagged) => tagged,
            Err(e) => {
                outcome.errors.push(format!(
                    "Processing: failed to construct reader auth payload: {e}"
                ));
                return outcome;
            }
        };

        let detached_payload = match cbor::to_vec(&detached_payload) {
            Ok(bytes) => bytes,
            Err(e) => {
                outcome.errors.push(format!(
                    "Processing: failed to encode reader auth payload: {e}"
                ));
                return outcome;
            }
        };

        let verification_outcome = reader_auth
            .verify::<VerifyingKey<NistP256>, p256::ecdsa::Signature>(
                &verifier,
                Some(&detached_payload),
                None,
            );

        if let Err(e) = verification_outcome.into_result() {
            outcome.errors.push(format!(
                "Verification: failed to verify reader auth signature: {e}"
            ))
        }

        outcome
    }
}

impl PreparedDeviceResponse {
    fn empty(status: Status) -> Self {
        PreparedDeviceResponse {
            status,
            prepared_documents: Vec::new(),
            document_errors: None,
            signed_documents: Vec::new(),
        }
    }

    /// Identifies that the response ready to be finalized.
    ///
    /// If `false`, then there are still items that need to be authorized.
    pub fn is_complete(&self) -> bool {
        self.prepared_documents.is_empty()
    }

    /// When there are documents to be signed, it will return then next one for signing.
    pub fn get_next_signature_payload(&self) -> Option<(Uuid, &[u8])> {
        self.prepared_documents
            .last()
            .map(|doc| (doc.id, doc.prepared_cose.signature_payload()))
    }

    /// Submit the externally signed signature for object
    /// returned by [PreparedDeviceResponse::get_next_signature_payload].
    pub fn submit_next_signature(&mut self, signature: Vec<u8>) {
        let signed_doc = match self.prepared_documents.pop() {
            Some(doc) => doc.finalize(signature),
            None => {
                //tracing::error!(
                //    "received a signature for finalising when there are no more prepared docs"
                //);
                return;
            }
        };
        self.signed_documents.push(signed_doc);
    }

    /// Will finalize and prepare the device response.
    pub fn finalize_response(self) -> DeviceResponse {
        if !self.is_complete() {
            //tracing::warn!("attempt to finalize PreparedDeviceResponse before all prepared documents had been authorized");
            return PreparedDeviceResponse::empty(Status::GeneralError).finalize_response();
        }

        DeviceResponse {
            version: DeviceResponse::VERSION.into(),
            documents: self.signed_documents.try_into().ok(),
            document_errors: self.document_errors,
            status: self.status,
        }
    }
}

impl PreparedDocument {
    fn finalize(self, signature: Vec<u8>) -> DeviceResponseDoc {
        let Self {
            issuer_signed,
            device_namespaces,
            prepared_cose,
            errors,
            doc_type,
            ..
        } = self;
        let device_auth = match prepared_cose {
            PreparedCose::Sign1(inner) => DeviceAuth::DeviceSignature(inner.finalize(signature)),
            PreparedCose::Mac0(inner) => DeviceAuth::DeviceMac(inner.finalize(signature)),
        };
        let device_signed = DeviceSigned {
            namespaces: device_namespaces,
            device_auth,
        };
        DeviceResponseDoc {
            doc_type,
            issuer_signed,
            device_signed,
            errors,
        }
    }
}

/// Keeps the device session data.
///
/// One implementation is [SessionManager].
pub trait DeviceSession {
    type ST: SessionTranscript;

    /// Get the device documents.
    fn documents(&self) -> &Documents;
    fn session_transcript(&self) -> Self::ST;
    fn device_auth_type(&self) -> DeviceAuthType;

    /// Prepare the response based on the requested items and permitted ones.
    fn prepare_response(
        &self,
        requests: &RequestedItems,
        permitted: PermittedItems,
    ) -> PreparedDeviceResponse {
        let mut prepared_documents: Vec<PreparedDocument> = Vec::new();
        let mut document_errors: Vec<DocumentError> = Vec::new();

        for (doc_type, namespaces) in filter_permitted(requests, permitted).into_iter() {
            let document = match self.documents().get(&doc_type) {
                Some(doc) => doc,
                None => {
                    // tracing::error!("holder owns no documents of type {}", doc_type);
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let signature_algorithm = match document
                .mso
                .device_key_info
                .device_key
                .signature_algorithm()
            {
                Some(alg) => alg,
                None => {
                    //tracing::error!(
                    //    "device key for document '{}' cannot perform signing",
                    //    document.id
                    //);
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };

            let mut issuer_namespaces: BTreeMap<String, NonEmptyVec<IssuerSignedItemBytes>> =
                Default::default();
            let mut errors: BTreeMap<String, NonEmptyMap<String, DocumentErrorCode>> =
                Default::default();

            for (namespace, elements) in namespaces.into_iter() {
                if let Some(issuer_items) = document.namespaces.get(&namespace) {
                    for element_identifier in elements.into_iter() {
                        if let Some(item) = issuer_items.get(&element_identifier) {
                            if let Some(returned_items) = issuer_namespaces.get_mut(&namespace) {
                                returned_items.push(item.clone());
                            } else {
                                let returned_items = NonEmptyVec::new(item.clone());
                                issuer_namespaces.insert(namespace.clone(), returned_items);
                            }
                        } else if let Some(returned_errors) = errors.get_mut(&namespace) {
                            returned_errors
                                .insert(element_identifier, DocumentErrorCode::DataNotReturned);
                        } else {
                            let returned_errors = NonEmptyMap::new(
                                element_identifier,
                                DocumentErrorCode::DataNotReturned,
                            );
                            errors.insert(namespace.clone(), returned_errors);
                        }
                    }
                } else {
                    for element_identifier in elements.into_iter() {
                        if let Some(returned_errors) = errors.get_mut(&namespace) {
                            returned_errors
                                .insert(element_identifier, DocumentErrorCode::DataNotReturned);
                        } else {
                            let returned_errors = NonEmptyMap::new(
                                element_identifier,
                                DocumentErrorCode::DataNotReturned,
                            );
                            errors.insert(namespace.clone(), returned_errors);
                        }
                    }
                }
            }

            let device_namespaces = match Tag24::new(Default::default()) {
                Ok(dp) => dp,
                Err(_e) => {
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth = DeviceAuthentication::new(
                self.session_transcript(),
                doc_type.clone(),
                device_namespaces.clone(),
            );
            let device_auth = match Tag24::new(device_auth) {
                Ok(da) => da,
                Err(_e) => {
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth_bytes = match cbor::to_vec(&device_auth) {
                Ok(dab) => dab,
                Err(_e) => {
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let header = coset::HeaderBuilder::new()
                .algorithm(signature_algorithm)
                .build();

            let prepared_cose = match self.device_auth_type() {
                DeviceAuthType::Sign1 => {
                    let cose_sign1_builder = CoseSign1Builder::new().protected(header);
                    let prepared_cose_sign1 = match PreparedCoseSign1::new(
                        cose_sign1_builder,
                        Some(&device_auth_bytes),
                        None,
                        false,
                    ) {
                        Ok(prepared) => prepared,
                        Err(_e) => {
                            let error: DocumentError =
                                [(doc_type, DocumentErrorCode::DataNotReturned)]
                                    .into_iter()
                                    .collect();
                            document_errors.push(error);
                            continue;
                        }
                    };
                    PreparedCose::Sign1(prepared_cose_sign1)
                }
                DeviceAuthType::Mac0 => {
                    let cose_mac0_builder = CoseMac0Builder::new().protected(header);
                    let prepared_cose_mac0 = match PreparedCoseMac0::new(
                        cose_mac0_builder,
                        Some(&device_auth_bytes),
                        None,
                        false,
                    ) {
                        Ok(prepared) => prepared,
                        Err(_e) => {
                            let error: DocumentError =
                                [(doc_type, DocumentErrorCode::DataNotReturned)]
                                    .into_iter()
                                    .collect();
                            document_errors.push(error);
                            continue;
                        }
                    };
                    PreparedCose::Mac0(prepared_cose_mac0)
                }
            };

            let prepared_document = PreparedDocument {
                id: document.id,
                doc_type,
                issuer_signed: IssuerSigned {
                    namespaces: issuer_namespaces.try_into().ok(),
                    issuer_auth: document.issuer_auth.clone(),
                },
                device_namespaces,
                prepared_cose,
                errors: errors.try_into().ok(),
            };
            prepared_documents.push(prepared_document);
        }
        PreparedDeviceResponse {
            prepared_documents,
            document_errors: document_errors.try_into().ok(),
            status: Status::OK,
            signed_documents: Vec::new(),
        }
    }
}

impl DeviceSession for SessionManager {
    type ST = SessionTranscript180135;

    fn documents(&self) -> &Documents {
        &self.documents
    }

    fn session_transcript(&self) -> SessionTranscript180135 {
        self.session_transcript.clone()
    }

    fn device_auth_type(&self) -> DeviceAuthType {
        self.device_auth_type
    }
}

impl From<Mdoc> for Document {
    fn from(mdoc: Mdoc) -> Document {
        fn extract(
            v: NonEmptyVec<IssuerSignedItemBytes>,
        ) -> NonEmptyMap<ElementIdentifier, IssuerSignedItemBytes> {
            v.into_inner()
                .into_iter()
                .map(|i| (i.as_ref().element_identifier.clone(), i))
                .collect::<BTreeMap<_, _>>()
                .try_into()
                // Can unwrap as there is always at least one element in a NonEmptyVec.
                .unwrap()
        }

        let Mdoc {
            mso,
            namespaces,
            issuer_auth,
            ..
        } = mdoc;
        let namespaces = namespaces
            .into_inner()
            .into_iter()
            .map(|(ns, v)| (ns, extract(v)))
            .collect::<BTreeMap<_, _>>()
            .try_into()
            // Can unwrap as there is always at least one element in a NonEmptyMap.
            .unwrap();

        Document {
            id: Uuid::now_v1(&[0, 0, 0, 0, 0, 0]),
            mso,
            namespaces,
            issuer_auth,
        }
    }
}

/// Filter permitted items to only permit the items that were requested.
pub fn filter_permitted(request: &RequestedItems, permitted: PermittedItems) -> PermittedItems {
    permitted
        .into_iter()
        .filter_map(|(doc_type, namespaces)| {
            request
                .iter()
                .find(|item| item.doc_type == doc_type)
                .map(|item| {
                    namespaces
                        .into_iter()
                        .filter_map(|(ns, elems)| {
                            item.namespaces
                                .get(&ns)
                                .map(|req_elems| {
                                    elems
                                        .into_iter()
                                        .filter(|elem| req_elems.contains_key(elem))
                                        .collect()
                                })
                                .map(|e| (ns, e))
                        })
                        .collect()
                })
                .map(|ns| (doc_type, ns))
        })
        .collect()
}

pub fn nearest_age_attestation(
    element_identifier: String,
    issuer_items: NonEmptyMap<String, Tag24<IssuerSignedItem>>,
) -> Result<Option<Tag24<IssuerSignedItem>>, Error> {
    let requested_age: u8 = parse_age_from_element_identifier(element_identifier)?;

    //find closest age_over_nn field that is true
    let owned_age_over_claims: Vec<(String, Tag24<IssuerSignedItem>)> = issuer_items
        .into_inner()
        .into_iter()
        .filter(|element| element.0.contains("age_over"))
        .collect();

    let age_over_claims_numerical: Result<Vec<(u8, Tag24<IssuerSignedItem>)>, Error> =
        owned_age_over_claims
            .iter()
            .map(|f| {
                Ok((
                    parse_age_from_element_identifier(f.to_owned().0)?,
                    f.to_owned().1,
                ))
            })
            .collect();

    let (true_age_over_claims, false_age_over_claims): (Vec<_>, Vec<_>) =
        age_over_claims_numerical?.into_iter().partition(|x| {
            x.1.to_owned().into_inner().element_value == ciborium::Value::Bool(true)
        });

    let nearest_age_over = true_age_over_claims
        .iter()
        .filter(|f| f.0 >= requested_age)
        .min_by_key(|claim| claim.0);

    if let Some(age_attestation) = nearest_age_over {
        return Ok(Some(age_attestation.1.to_owned()));
        // if there is no appropriate true age attestation, find the closest false age attestation
    } else {
        let nearest_age_under = false_age_over_claims
            .iter()
            .filter(|f| f.0 <= requested_age)
            .max_by_key(|claim| claim.0);

        if let Some(age_attestation) = nearest_age_under {
            return Ok(Some(age_attestation.1.to_owned()));
        }
    }

    //if there is still no appropriate attestation, do not return a value
    Ok(None)
}

/// Will parse the corresponding age as a number from the `age_over_*` element identifier.
///
/// # Example
///
/// ```
/// use isomdl::presentation::device::parse_age_from_element_identifier;
///
/// let element = "age_over_21".to_string();
/// let age = parse_age_from_element_identifier(element).unwrap();
/// assert_eq!(age, 21);
/// ```
pub fn parse_age_from_element_identifier(element_identifier: String) -> Result<u8, Error> {
    Ok(AgeOver::try_from(element_identifier)?.0)
}

/// Holds the age part from the `age_over_*` element identifier.
pub struct AgeOver(u8);

impl TryFrom<String> for AgeOver {
    type Error = Error;
    fn try_from(element_identifier: String) -> Result<Self, Self::Error> {
        if let Some(x) = element_identifier.strip_prefix("age_over_") {
            let age_over = AgeOver(str::parse::<u8>(x)?);
            Ok(age_over)
        } else {
            Err(Error::PrefixError)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::definitions::helpers::ByteStr;

    use super::*;
    use crate::definitions::mso::DigestId;
    use serde_json::json;

    #[test]
    fn filter_permitted() {
        let requested = serde_json::from_value(json!([
            {
                "docType": "doc_type_1",
                "nameSpaces": {
                    "namespace_1": {
                        "element_1": false,
                        "element_2": false,
                    },
                    "namespace_2": {
                        "element_1": false,
                    }
                }
            },
            {
                "docType": "doc_type_2",
                "nameSpaces": {
                    "namespace_1": {
                        "element_1": false,
                    }
                }
            }
        ]))
        .unwrap();
        let permitted = serde_json::from_value(json!({
            "doc_type_1": {
                "namespace_1": [
                    "element_1",
                    "element_3"
                ],
                "namespace_3": [
                    "element_1",
                ]
            },
            "doc_type_3": {
                "namespace_1": [
                    "element_1",
                ],
            }
        }))
        .unwrap();
        let expected: PermittedItems = serde_json::from_value(json!({
            "doc_type_1": {
                "namespace_1": [
                    "element_1",
                ],
            }
        }))
        .unwrap();

        let filtered = super::filter_permitted(&requested, permitted);

        assert_eq!(expected, filtered);
    }

    #[test]
    fn test_parse_age_from_element_identifier() {
        let element_identifier = "age_over_88".to_string();
        let age = parse_age_from_element_identifier(element_identifier).unwrap();
        assert_eq!(age, 88)
    }

    #[test]
    fn test_age_attestation_response() {
        let requested_element_identifier = "age_over_23".to_string();
        let element_identifier1 = "age_over_18".to_string();
        let element_identifier2 = "age_over_22".to_string();
        let element_identifier3 = "age_over_21".to_string();

        let random = vec![1, 2, 3, 4, 5];
        let issuer_signed_item1 = IssuerSignedItem {
            digest_id: DigestId::new(1),
            random: ByteStr::from(random.clone()),
            element_identifier: element_identifier1.clone(),
            element_value: ciborium::Value::Bool(true),
        };

        let issuer_signed_item2 = IssuerSignedItem {
            digest_id: DigestId::new(2),
            random: ByteStr::from(random.clone()),
            element_identifier: element_identifier2.clone(),
            element_value: ciborium::Value::Bool(false),
        };

        let issuer_signed_item3 = IssuerSignedItem {
            digest_id: DigestId::new(3),
            random: ByteStr::from(random),
            element_identifier: element_identifier3.clone(),
            element_value: ciborium::Value::Bool(false),
        };

        let issuer_item1 = Tag24::new(issuer_signed_item1).unwrap();
        let issuer_item2 = Tag24::new(issuer_signed_item2).unwrap();
        let issuer_item3 = Tag24::new(issuer_signed_item3).unwrap();
        let mut issuer_items = NonEmptyMap::new(element_identifier1, issuer_item1);
        issuer_items.insert(element_identifier2, issuer_item2.clone());
        issuer_items.insert(element_identifier3, issuer_item3);

        let result = nearest_age_attestation(requested_element_identifier, issuer_items)
            .expect("failed to process age attestation request");

        assert_eq!(result.unwrap().inner_bytes, issuer_item2.inner_bytes);
    }

    #[test]
    fn test_str_to_u8() {
        let wib = "8";
        let x = wib.as_bytes();

        println!("{:?}", x);
    }
}
