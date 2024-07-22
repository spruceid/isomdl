use std::collections::BTreeMap;
use std::num::ParseIntError;

use coset::{CoseSign1Builder, Header, RegisteredLabelWithPrivate};
use p256::FieldBytes;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use uuid::Uuid;

use session::SessionTranscript180135;

use crate::cose::sign1::CoseSign1;
use crate::cose::Cose;
use crate::definitions::IssuerSignedItem;
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
        session::{
            self, derive_session_key, get_shared_secret, Handover, SessionData, SessionTranscript,
        },
        CoseKey, DeviceEngagement, DeviceResponse, Mso, SessionEstablishment,
    },
    issuance::Mdoc,
};

#[derive(Serialize, Deserialize)]
pub struct SessionManagerInit {
    documents: Documents,
    e_device_key: Vec<u8>,
    device_engagement: Tag24<DeviceEngagement>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionManagerEngaged {
    documents: Documents,
    e_device_key: Vec<u8>,
    device_engagement: Tag24<DeviceEngagement>,
    handover: Handover,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionManager {
    documents: Documents,
    session_transcript: SessionTranscript180135,
    sk_device: [u8; 32],
    device_message_counter: u32,
    sk_reader: [u8; 32],
    reader_message_counter: u32,
    state: State,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    #[error("could not parse age attestation claim")]
    ParsingError(#[from] ParseIntError),
    #[error("age_over element identifier is malformed")]
    PrefixError,
}

pub type Documents = NonEmptyMap<DocType, Document>;
type DocType = String;

/// Device-internal document datatype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: Uuid,
    pub issuer_auth: CoseSign1,
    pub mso: Mso,
    pub namespaces: Namespaces,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedDeviceResponse {
    prepared_documents: Vec<PreparedDocument>,
    signed_documents: Vec<DeviceResponseDoc>,
    document_errors: Option<DocumentErrors>,
    status: Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreparedDocument {
    id: Uuid,
    doc_type: String,
    issuer_signed: IssuerSigned,
    device_namespaces: DeviceNamespacesBytes,
    prepared_cose_sign1: CoseSign1,
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
            .map(|DocRequest { items_request, .. }| items_request.into_inner())
            .collect())
    }

    pub fn prepare_response(&mut self, requests: &RequestedItems, permitted: PermittedItems) {
        let prepared_response = DeviceSession::prepare_response(self, requests, permitted);
        self.state = State::Signing(prepared_response);
    }

    fn handle_decoded_request(&mut self, request: SessionData) -> anyhow::Result<RequestedItems> {
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
    pub fn handle_request(&mut self, request: &[u8]) -> anyhow::Result<RequestedItems> {
        let session_data: SessionData = serde_cbor::from_slice(request)?;
        self.handle_decoded_request(session_data)
    }

    /// Get the next payload for signing.
    pub fn get_next_signature_payload(&self) -> Option<(Uuid, &[u8])> {
        match &self.state {
            State::Signing(p) => p.get_next_signature_payload(),
            _ => None,
        }
    }

    /// Submit the externally signed signature.
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
            mut prepared_cose_sign1,
            errors,
            doc_type,
            ..
        } = self;
        prepared_cose_sign1.set_signature(signature);
        let device_signed = DeviceSigned {
            namespaces: device_namespaces,
            // todo: support for CoseMac0
            device_auth: DeviceAuth::Signature {
                device_signature: prepared_cose_sign1,
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
    type ST: SessionTranscript;

    fn documents(&self) -> &Documents;
    fn session_transcript(&self) -> Self::ST;
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
            let device_auth_bytes = match serde_cbor::to_vec(&device_auth) {
                Ok(dab) => dab,
                Err(_e) => {
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let protected = Header {
                alg: Some(RegisteredLabelWithPrivate::Assigned(signature_algorithm)),
                ..Header::default()
            };
            // todo: support for CoseMac0
            let builder = CoseSign1Builder::new()
                .protected(protected)
                .payload(device_auth_bytes);
            let prepared_cose_sign1 = CoseSign1::new(builder.build());
            let prepared_document = PreparedDocument {
                id: document.id,
                doc_type,
                issuer_signed: IssuerSigned {
                    namespaces: issuer_namespaces.try_into().ok(),
                    issuer_auth: document.issuer_auth.clone(),
                },
                device_namespaces,
                // todo: support for CoseMac0
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
    type ST = SessionTranscript180135;

    fn documents(&self) -> &Documents {
        &self.documents
    }

    fn session_transcript(&self) -> SessionTranscript180135 {
        self.session_transcript.clone()
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
        age_over_claims_numerical?
            .into_iter()
            .partition(|x| x.1.to_owned().into_inner().element_value == CborValue::Bool(true));

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

pub fn parse_age_from_element_identifier(element_identifier: String) -> Result<u8, Error> {
    Ok(AgeOver::try_from(element_identifier)?.0)
}

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
    use coset::{iana, CborSerializable, CoseSign1Builder};
    use ecdsa::Signature;
    use hex::FromHex;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::{NistP256, SecretKey};
    use serde_json::json;
    use signature::{Signer, Verifier};

    use crate::definitions::helpers::ByteStr;
    use crate::definitions::mso::DigestId;

    use super::*;

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
            element_value: CborValue::Bool(true),
        };

        let issuer_signed_item2 = IssuerSignedItem {
            digest_id: DigestId::new(2),
            random: ByteStr::from(random.clone()),
            element_identifier: element_identifier2.clone(),
            element_value: CborValue::Bool(false),
        };

        let issuer_signed_item3 = IssuerSignedItem {
            digest_id: DigestId::new(3),
            random: ByteStr::from(random),
            element_identifier: element_identifier3.clone(),
            element_value: CborValue::Bool(false),
        };

        let issuer_item1 = Tag24::new(issuer_signed_item1).unwrap();
        let issuer_item2 = Tag24::new(issuer_signed_item2).unwrap();
        let issuer_item3 = Tag24::new(issuer_signed_item3).unwrap();
        let mut issuer_items = NonEmptyMap::new(element_identifier1, issuer_item1.clone());
        issuer_items.insert(element_identifier2, issuer_item2.clone());
        issuer_items.insert(element_identifier3, issuer_item3.clone());

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

    // static COSE_SIGN1: &str = include_str!("../../test/definitions/cose/sign1/serialized.cbor");
    static COSE_KEY: &str = include_str!("../../test/definitions/cose/sign1/secret_key");

    fn sign(payload: &[u8]) -> Vec<u8> {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();

        let sig: Signature<NistP256> = signer.try_sign(payload).unwrap();
        sig.to_vec()
    }

    fn verify(sig: &[u8], payload: &[u8]) -> coset::Result<(), String> {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();
        let verifier: VerifyingKey = (&signer).into();
        let signature: Signature<NistP256> =
            Signature::from_slice(sig).map_err(|err| err.to_string())?;
        verifier
            .verify(payload, &signature)
            .map_err(|err| err.to_string())
    }

    #[test]
    fn test_coset() {
        // Inputs.
        let pt = b"This is the content";
        let aad = b"this is additional data";

        // Build a `CoseSign1` object.
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(b"11".to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(pt.to_vec())
            .create_signature(aad, sign) // closure to do sign operation
            .build();

        // Serialize to bytes.
        let sign1_data = sign1.to_vec().unwrap();
        println!(
            "'{}' + '{}' => {}",
            String::from_utf8_lossy(pt),
            String::from_utf8_lossy(aad),
            hex::encode(&sign1_data)
        );

        // At the receiving end, deserialize the bytes back to a `CoseSign1` object.
        let mut sign1 = coset::CoseSign1::from_slice(&sign1_data).unwrap();

        // At this point, real code would validate the protected headers.

        // Check the signature, which needs to have the same `aad` provided, by
        // providing a closure that can do the verify operation.
        let result = sign1.verify_signature(aad, verify);
        println!("Signature verified: {:?}.", result);
        assert!(result.is_ok());

        // Changing an unprotected header leaves the signature valid.
        sign1.unprotected.content_type = Some(coset::ContentType::Text("text/plain".to_owned()));
        assert!(sign1.verify_signature(aad, verify).is_ok());

        // Providing a different `aad` means the signature won't validate.
        assert!(sign1.verify_signature(b"not aad", verify).is_err());

        // Changing a protected header invalidates the signature.
        sign1.protected.original_data = None;
        sign1.protected.header.content_type =
            Some(coset::ContentType::Text("text/plain".to_owned()));
        assert!(sign1.verify_signature(aad, verify).is_err());
    }
}
