//! Mdoc authentication.
//!
//! 1. As part of mdoc response, mdl produces `DeviceAuth`, which is either a `DeviceSignature` or
//!    a `DeviceMac`.
//!
//! 2. The reader must authenticate that `DeviceKey` in the MSO is the key that generated the
//!    `DeviceAuth`.
//!
//! 3. The reader must authenticate that the `DeviceKey` is authorized by `KeyAuthorizations` to
//!    sign over the data elements present in `DeviceNameSpaces`.

use crate::definitions::{
    device_request::DeviceRequest,
    device_response::{
        Document as DeviceResponseDoc, DocumentError, DocumentErrorCode, DocumentErrors,
        Errors as NamespaceErrors, Status,
    },
    device_signed::{
        DeviceAuth, DeviceAuthentication, DeviceNamespacesBytes, DeviceSigned, DeviceSignedItems,
    },
    helpers::{NonEmptyMap, NonEmptyVec, Tag24},
    issuer_signed::{IssuerSigned, IssuerSignedItemBytes},
    DeviceResponse, Mso, SessionTranscript,
};
use cose_rs::sign1::{CoseSign1, PreparedCoseSign1};
use serde_cbor::Value as CborValue;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Holder {
    documents: Documents,
}

// TODO: Do we need to support multiple documents of the same type?
type Documents = NonEmptyMap<DocType, Document>;
type DocType = String;

/// Holder-internal document datatype.
#[derive(Debug, Clone)]
struct Document {
    id: Uuid,
    issuer_auth: CoseSign1,
    mso: Mso,
    namespaces: Namespaces,
}

#[derive(Debug, Clone)]
pub struct PreparedDeviceResponse {
    prepared_documents: Vec<PreparedDocument>,
    signed_documents: Vec<DeviceResponseDoc>,
    document_errors: Option<DocumentErrors>,
    status: Status,
}

#[derive(Debug, Clone)]
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

impl Holder {
    pub fn prepare_response(
        &self,
        session: SessionTranscript,
        request: &[u8],
    ) -> PreparedDeviceResponse {
        let request: CborValue = match serde_cbor::from_slice(request) {
            Ok(cbor) => cbor,
            Err(error) => {
                tracing::error!("unable to decode DeviceRequest bytes as cbor: {}", error);
                return PreparedDeviceResponse::empty(Status::CborDecodingError);
            }
        };

        let request: DeviceRequest = match serde_cbor::value::from_value(request) {
            Ok(cbor) => cbor,
            Err(error) => {
                tracing::error!("unable to validate DeviceRequest cbor: {}", error);
                return PreparedDeviceResponse::empty(Status::CborValidationError);
            }
        };

        if request.version != DeviceRequest::VERSION {
            tracing::error!(
                "unsupported DeviceRequest version: {} ({} is supported)",
                request.version,
                DeviceRequest::VERSION
            );
            return PreparedDeviceResponse::empty(Status::GeneralError);
        }

        let mut prepared_documents: Vec<PreparedDocument> = Vec::new();
        let mut document_errors: Vec<DocumentError> = Vec::new();

        for doc_request in request.doc_requests.into_inner().into_iter() {
            if let Some(_reader_auth) = doc_request.reader_auth.as_ref() {
                // TODO: implement reader auth
            }

            let items_request = doc_request.items_request.into_inner();
            let doc_type = items_request.doc_type;
            let document = match self.documents.get(&doc_type) {
                Some(doc) => doc,
                None => {
                    tracing::error!("holder owns no documents of type {}", doc_type);
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
                    tracing::error!(
                        "device key for document '{}' cannot perform signing",
                        document.id
                    );
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };

            if let Some(_info) = items_request.request_info.as_ref() {
                // Current version of mdl spec doesn't use request info.
            }

            let mut issuer_namespaces: HashMap<String, NonEmptyVec<IssuerSignedItemBytes>> =
                Default::default();
            let mut device_namespaces: HashMap<String, DeviceSignedItems> = Default::default();
            let mut errors: HashMap<String, NonEmptyMap<String, DocumentErrorCode>> =
                Default::default();

            for (namespace, elements) in items_request.namespaces.into_inner().into_iter() {
                if let Some(issuer_items) = document.namespaces.get(&namespace) {
                    for (element_identifier, _intent_to_retain) in elements.into_inner().into_iter()
                    {
                        if let Some(item) = issuer_items.get(&element_identifier) {
                            // TODO: use intent_to_retain: notify user for approval?
                            if let Some(returned_items) = issuer_namespaces.get_mut(&namespace) {
                                returned_items.push(item.clone());
                            } else {
                                let returned_items = NonEmptyVec::new(item.clone());
                                issuer_namespaces.insert(namespace.clone(), returned_items);
                            }
                            let device_key_permitted = document
                                .mso
                                .device_key_info
                                .key_authorizations
                                .as_ref()
                                .map(|auth| auth.permitted(&namespace, &element_identifier))
                                .unwrap_or(false);
                            if device_key_permitted {
                                if let Some(device_items) = device_namespaces.get_mut(&namespace) {
                                    device_items.insert(
                                        element_identifier,
                                        item.as_ref().element_value.clone(),
                                    );
                                } else {
                                    let device_signed = NonEmptyMap::new(
                                        element_identifier,
                                        item.as_ref().element_value.clone(),
                                    );
                                    device_namespaces.insert(namespace.clone(), device_signed);
                                }
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
                    for (element_identifier, _) in elements.into_inner().into_iter() {
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

            let device_namespaces = match Tag24::new(device_namespaces) {
                Ok(dp) => dp,
                Err(e) => {
                    tracing::error!("failed to convert device namespaces to cbor: {}", e);
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth =
                DeviceAuthentication::new(session.clone(), doc_type.clone(), device_namespaces);
            let device_auth = match Tag24::new(device_auth) {
                Ok(da) => da,
                Err(e) => {
                    tracing::error!("failed to convert device authentication to cbor: {}", e);
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let prepared_cose_sign1 = match CoseSign1::builder()
                .detached()
                .payload(device_auth.inner_bytes.clone())
                .signature_algorithm(signature_algorithm)
                .prepare()
            {
                Ok(prepared) => prepared,
                Err(e) => {
                    tracing::error!("failed to prepare COSE_Sign1: {}", e);
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
                device_namespaces: device_auth.into_inner().3,
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

    pub fn next_id(&self) -> Option<Uuid> {
        self.prepared_documents.last().map(|doc| doc.id)
    }

    pub fn next_signature_payload(&self) -> Option<&[u8]> {
        self.prepared_documents
            .last()
            .map(|doc| doc.prepared_cose_sign1.signature_payload())
    }

    pub fn finalize_next_signature(&mut self, signature: Vec<u8>) {
        let signed_doc = match self.prepared_documents.pop() {
            Some(doc) => doc.finalize(signature),
            None => {
                tracing::error!(
                    "received a signature for finalising when there are no more prepared docs"
                );
                return;
            }
        };
        self.signed_documents.push(signed_doc);
    }

    pub fn finalize_response(self) -> DeviceResponse {
        if !self.is_complete() {
            tracing::warn!("attempt to finalize PreparedDeviceResponse before all prepared documents had been authorized");
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
