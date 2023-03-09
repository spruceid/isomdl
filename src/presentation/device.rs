use crate::{
    definitions::{
        device_engagement::{DeviceRetrievalMethod, Security, ServerRetrievalMethods},
        device_request::{DeviceRequest, DocRequest, ItemsRequest},
        device_response::{
            Document as DeviceResponseDoc, DocumentError, DocumentErrorCode, DocumentErrors,
            Errors as NamespaceErrors, Status,
        },
        device_signed::{DeviceAuth, DeviceAuthentication, DeviceNamespacesBytes, DeviceSigned},
        helpers::{tag24, NonEmptyMap, NonEmptyVec, Tag24},
        issuer_signed::{IssuerSigned, IssuerSignedItemBytes},
        session::{self, derive_session_key, get_shared_secret, Handover, SessionData},
        CoseKey, DeviceEngagement, DeviceResponse, Mso, SessionEstablishment, SessionTranscript,
    },
    issuance::Mdoc,
};
use cose_rs::sign1::{CoseSign1, PreparedCoseSign1};
use p256::FieldBytes;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::collections::BTreeMap;
use uuid::Uuid;

pub mod oid4vp;

// TODO: Consider removing serde derivations down the line as Tag24 does not round-trip with
// non-cbor serde implementors.
// TODO: If we stored secret key bytes, it must implement Zeroize on Drop
#[derive(Serialize, Deserialize)]
pub struct SessionManagerInit {
    documents: Documents,
    e_device_key: Vec<u8>,
    device_engagement: Tag24<DeviceEngagement>,
}

// TODO: Consider removing serde derivations down the line as Tag24 does not round-trip with
// non-cbor serde implementors.
#[derive(Serialize, Deserialize)]
pub struct SessionManagerEngaged {
    documents: Documents,
    e_device_key: Vec<u8>,
    device_engagement: Tag24<DeviceEngagement>,
    handover: Handover,
}

// TODO: Consider removing serde derivations down the line as Tag24 does not round-trip with
// non-cbor serde implementors.
#[derive(Serialize, Deserialize)]
pub struct SessionManager {
    documents: Documents,
    session_transcript: Tag24<SessionTranscript>,
    sk_device: [u8; 32],
    device_message_counter: u32,
    sk_reader: [u8; 32],
    reader_message_counter: u32,
    state: State,
}

#[derive(Clone, Debug, Default)]
// TODO: Consider removing serde derivations down the line as Tag24 does not round-trip with
// non-cbor serde implementors.
#[derive(Serialize, Deserialize)]
pub enum State {
    #[default]
    AwaitingRequest,
    Signing(PreparedDeviceResponse),
    ReadyToRespond(Vec<u8>),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to generate ephemeral key: {0}")]
    EKeyGeneration(session::Error),
    #[error("error encoding value to CBOR: {0}")]
    Tag24CborEncoding(tag24::Error),
    #[error("unable to generate shared secret: {0}")]
    SharedSecretGeneration(anyhow::Error),
    #[error("error encoding value to CBOR: {0}")]
    CborEncoding(serde_cbor::Error),
    #[error("session manager was used incorrectly")]
    ApiMisuse,
}

// TODO: Do we need to support multiple documents of the same type?
pub type Documents = NonEmptyMap<DocType, Document>;
type DocType = String;

/// Device-internal document datatype.
#[derive(Debug, Clone)]
// TODO: Consider removing serde derivations down the line as Tag24 does not round-trip with
// non-cbor serde implementors.
#[derive(Serialize, Deserialize)]
pub struct Document {
    pub id: Uuid,
    pub issuer_auth: CoseSign1,
    pub mso: Mso,
    pub namespaces: Namespaces,
}

#[derive(Debug, Clone)]
// TODO: Consider removing serde derivations down the line as Tag24 does not round-trip with
// non-cbor serde implementors.
#[derive(Serialize, Deserialize)]
pub struct PreparedDeviceResponse {
    prepared_documents: Vec<PreparedDocument>,
    signed_documents: Vec<DeviceResponseDoc>,
    document_errors: Option<DocumentErrors>,
    status: Status,
}

#[derive(Debug, Clone)]
// TODO: Consider removing serde derivations down the line as Tag24 does not round-trip with
// non-cbor serde implementors.
#[derive(Serialize, Deserialize)]
struct PreparedDocument {
    id: Uuid,
    doc_type: String,
    issuer_signed: IssuerSigned,
    device_namespaces: DeviceNamespacesBytes,
    prepared_cose_sign1: PreparedCoseSign1,
    errors: Option<NamespaceErrors>,
}

type Namespaces = NonEmptyMap<Namespace, NonEmptyMap<ElementIdentifier, IssuerSignedItemBytes>>;
type Namespace = String;
type ElementIdentifier = String;

pub type RequestedItems = Vec<ItemsRequest>;
pub type PermittedItems = BTreeMap<DocType, BTreeMap<Namespace, Vec<ElementIdentifier>>>;

impl SessionManagerInit {
    /// Initialise the SessionManager.
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

    /// Begin device engagement using QR code.
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
    pub fn process_session_establishment(
        self,
        session_establishment: SessionEstablishment,
    ) -> anyhow::Result<(SessionManager, RequestedItems)> {
        let e_reader_key = session_establishment.e_reader_key;
        let session_transcript = Tag24::new(SessionTranscript(
            self.device_engagement,
            e_reader_key.clone(),
            self.handover,
        ))
        .map_err(Error::Tag24CborEncoding)?;

        let e_device_key = p256::SecretKey::from_bytes(FieldBytes::from_slice(&self.e_device_key))?;

        let shared_secret = get_shared_secret(e_reader_key.into_inner(), &e_device_key.into())
            .map_err(Error::SharedSecretGeneration)?;

        let sk_reader = derive_session_key(&shared_secret, &session_transcript, true)?.into();
        let sk_device = derive_session_key(&shared_secret, &session_transcript, false)?.into();

        let mut sm = SessionManager {
            documents: self.documents,
            session_transcript,
            sk_device,
            device_message_counter: 0,
            sk_reader,
            reader_message_counter: 0,
            state: State::AwaitingRequest,
        };

        let requested_data = sm.handle_decoded_request(SessionData {
            data: Some(session_establishment.data),
            status: None,
        })?;

        Ok((sm, requested_data))
    }
}

impl SessionManager {
    fn parse_request(&self, request: &[u8]) -> Result<DeviceRequest, PreparedDeviceResponse> {
        let request: CborValue = serde_cbor::from_slice(request).map_err(|_| {
            // tracing::error!("unable to decode DeviceRequest bytes as cbor: {}", error);
            PreparedDeviceResponse::empty(Status::CborDecodingError)
        })?;

        serde_cbor::value::from_value(request).map_err(|_| {
            // tracing::error!("unable to validate DeviceRequest cbor: {}", error);
            PreparedDeviceResponse::empty(Status::CborValidationError)
        })
    }

    fn validate_request(
        &self,
        request: DeviceRequest,
    ) -> Result<Vec<ItemsRequest>, PreparedDeviceResponse> {
        if request.version != DeviceRequest::VERSION {
            // tracing::error!(
            //     "unsupported DeviceRequest version: {} ({} is supported)",
            //     request.version,
            //     DeviceRequest::VERSION
            // );
            return Err(PreparedDeviceResponse::empty(Status::GeneralError));
        }
        Ok(request
            .doc_requests
            .into_inner()
            .into_iter()
            .map(|DocRequest { items_request, .. }|
                 // TODO: implement reader auth
                 items_request.into_inner())
            .collect())
    }

    pub fn prepare_response(&mut self, requests: &RequestedItems, permitted: PermittedItems) {
        let prepared_response = DeviceSession::prepare_response(self, requests, permitted);
        self.state = State::Signing(prepared_response);
    }

    fn handle_decoded_request(&mut self, request: SessionData) -> anyhow::Result<RequestedItems> {
        // TODO: Better handling for termination status and missing data.
        let data = request.data.ok_or_else(|| {
            anyhow::anyhow!("no mdoc requests received, assume session can be terminated")
        })?;
        let decrypted_request = session::decrypt_reader_data(
            &self.sk_reader.into(),
            data.as_ref(),
            &mut self.reader_message_counter,
        )
        .map_err(|e| anyhow::anyhow!("unable to decrypt request: {}", e))?;
        let request = match self.parse_request(&decrypted_request) {
            Ok(r) => r,
            Err(e) => {
                self.state = State::Signing(e);
                return Ok(Default::default());
            }
        };
        let request = match self.validate_request(request) {
            Ok(r) => r,
            Err(e) => {
                self.state = State::Signing(e);
                return Ok(Default::default());
            }
        };
        Ok(request)
    }

    /// Handle a request from the reader.
    // TODO: Improve error handling.
    pub fn handle_request(&mut self, request: &[u8]) -> anyhow::Result<RequestedItems> {
        // TODO: Check session manager state.
        let session_data: SessionData = serde_cbor::from_slice(request)?;
        self.handle_decoded_request(session_data)
    }

    /// Get next payload for signing.
    pub fn get_next_signature_payload(&self) -> Option<(Uuid, &[u8])> {
        match &self.state {
            State::Signing(p) => p.get_next_signature_payload(),
            _ => None,
        }
    }

    /// Submit the externally signed signature.
    // TODO: Remove Result -- is unnecessary if we make cbor encoding infallible.
    pub fn submit_next_signature(&mut self, signature: Vec<u8>) -> anyhow::Result<()> {
        if matches!(self.state, State::Signing(_)) {
            match std::mem::take(&mut self.state) {
                State::Signing(mut p) => {
                    p.submit_next_signature(signature);
                    if p.is_complete() {
                        let response = p.finalize_response();
                        let mut status: Option<session::Status> = None;
                        let response_bytes = serde_cbor::to_vec(&response)?;
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
                        let encoded_response = serde_cbor::to_vec(&session_data)?;
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

    /// Identifies that the response is ready.
    pub fn response_ready(&self) -> bool {
        matches!(self.state, State::ReadyToRespond(_))
    }

    /// Retrieve the completed response.
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
    /// If false, then there are still items that need to be authorized.
    pub fn is_complete(&self) -> bool {
        self.prepared_documents.is_empty()
    }

    pub fn get_next_signature_payload(&self) -> Option<(Uuid, &[u8])> {
        self.prepared_documents
            .last()
            .map(|doc| (doc.id, doc.prepared_cose_sign1.signature_payload()))
    }

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
            prepared_cose_sign1,
            errors,
            doc_type,
            ..
        } = self;
        let cose_sign1 = prepared_cose_sign1.finalize(signature);
        let device_signed = DeviceSigned {
            namespaces: device_namespaces,
            device_auth: DeviceAuth::Signature {
                device_signature: cose_sign1,
            },
        };
        DeviceResponseDoc {
            doc_type,
            issuer_signed,
            device_signed,
            errors,
        }
    }
}

pub trait DeviceSession {
    fn documents(&self) -> &Documents;
    fn session_transcript(&self) -> &Tag24<SessionTranscript>;
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

            // TODO: Handle special cases, i.e. for `age_over_NN`.
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
                    //tracing::error!("failed to convert device namespaces to cbor: {}", e);
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth = DeviceAuthentication::new(
                self.session_transcript().as_ref().clone(),
                doc_type.clone(),
                device_namespaces.clone(),
            );
            let device_auth = match Tag24::new(device_auth) {
                Ok(da) => da,
                Err(_e) => {
                    //tracing::error!("failed to convert device authentication to cbor: {}", e);
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth_bytes = match serde_cbor::to_vec(&device_auth) {
                Ok(dab) => dab,
                Err(_e) => {
                    //tracing::error!("failed to convert device authentication to cbor: {}", e);
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let prepared_cose_sign1 = match CoseSign1::builder()
                .detached()
                .payload(device_auth_bytes)
                .signature_algorithm(signature_algorithm)
                .prepare()
            {
                Ok(prepared) => prepared,
                Err(_e) => {
                    //tracing::error!("failed to prepare COSE_Sign1: {}", e);
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
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
                prepared_cose_sign1,
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
    fn documents(&self) -> &Documents {
        &self.documents
    }

    fn session_transcript(&self) -> &Tag24<SessionTranscript> {
        &self.session_transcript
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
fn filter_permitted(request: &RequestedItems, permitted: PermittedItems) -> PermittedItems {
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

// TODO: Remove this function. This adds a temporary way to sign DeviceRequest for test mdocs.
pub fn sign_payload(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let der = include_str!("../../test/issuance/device_key.b64");
    let der_bytes = base64::decode(der)?;
    let key: p256::ecdsa::SigningKey = p256::SecretKey::from_sec1_der(&der_bytes)?.into();
    use signature::Signer;
    key.try_sign(payload)
        .map(|sig: p256::ecdsa::Signature| sig.to_vec())
        .map_err(Into::into)
}

#[cfg(test)]
mod test {
    use super::*;
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
}
