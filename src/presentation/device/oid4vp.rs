use super::{DeviceSession, Documents, PreparedDeviceResponse, RequestedItems};
use crate::definitions::oid4vp::DeviceResponse;
use crate::definitions::{
    device_engagement::Security,
    device_request::ItemsRequest,
    device_response::{DocumentError, DocumentErrorCode, Status},
    device_signed::AttendedDeviceAuthentication,
    helpers::{NonEmptyMap, NonEmptyVec, Tag24},
    issuer_signed::{IssuerSigned, IssuerSignedItemBytes},
    session::Handover,
    CoseKey, DeviceEngagement,
};
use crate::presentation::device::filter_permitted;
use crate::presentation::device::AttendedSessionTranscript;
use crate::presentation::device::PermittedItems;
use crate::presentation::device::PreparedDocument;
use anyhow::Result;
use cose_rs::CoseSign1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionManager {
    documents: Documents,
    session_transcript: AttendedSessionTranscript,
    requested_items: RequestedItems,
}

impl DeviceSession for SessionManager {
    type T = AttendedSessionTranscript;
    fn documents(&self) -> &Documents {
        &self.documents
    }

    fn session_transcript(&self) -> AttendedSessionTranscript {
        self.session_transcript.clone()
    }

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
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth = AttendedDeviceAuthentication::new(
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
            let prepared_cose_sign1 = match CoseSign1::builder()
                .detached()
                .payload(device_auth_bytes)
                .signature_algorithm(signature_algorithm)
                .prepare()
            {
                Ok(prepared) => prepared,
                Err(_e) => {
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

impl SessionManager {
    pub fn new<K>(
        documents: Documents,
        aud: String,
        nonce: String,
        e_verifier_key: K,
        _request: serde_json::Value,
    ) -> Result<Self>
    where
        K: TryInto<CoseKey>,
        <K as TryInto<CoseKey>>::Error: Sync + Send + std::error::Error + 'static,
    {
        let device_key = Tag24::new(
            documents
                .as_ref()
                .values()
                .next()
                .ok_or_else(|| anyhow::anyhow!("documents map was empty"))?
                .mso
                .device_key_info
                .device_key
                .clone(),
        )
        .unwrap();
        let device_engagement = Tag24::new(DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, device_key),
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        })?;
        let e_reader_key = Tag24::new(e_verifier_key.try_into()?)?;
        let handover = Handover::OID4VP(aud, nonce);

        let session_transcript =
            AttendedSessionTranscript(device_engagement, e_reader_key, handover);

        let requested_items = documents
            .as_ref()
            .values()
            .map(request_all)
            .collect::<Result<_, _>>()?;

        Ok(SessionManager {
            documents,
            session_transcript,
            requested_items,
        })
    }

    pub fn requested_items(&self) -> &RequestedItems {
        &self.requested_items
    }
}

/// Build a DocRequest for a Document for all data elements with no intent to retain.
fn request_all(document: &super::Document) -> Result<ItemsRequest> {
    let namespaces = document
        .namespaces
        .as_ref()
        .iter()
        .map(|(ns, elems)| {
            let elems: NonEmptyMap<String, bool> = elems
                .as_ref()
                .iter()
                .map(|(elem, _)| (elem.clone(), false))
                .collect::<BTreeMap<String, bool>>()
                .try_into()
                // Safe to unwrap as elems is initially a NonEmptyMap, so has at least one element.
                .unwrap();
            (ns.clone(), elems)
        })
        .collect::<BTreeMap<String, NonEmptyMap<String, bool>>>()
        .try_into()
        // Safe to unwrap as namespaces is initially a NonEmptyMap, so has at least one element.
        .unwrap();
    Ok(ItemsRequest {
        doc_type: document.mso.doc_type.clone(),
        request_info: None,
        namespaces,
    })
}

impl PreparedDeviceResponse {
    pub fn finalize_oid4vp_response(self) -> DeviceResponse {
        if !self.is_complete() {
            //tracing::warn!("attempt to finalize PreparedDeviceResponse before all prepared documents had been authorized");
            return PreparedDeviceResponse::empty(super::Status::GeneralError)
                .finalize_oid4vp_response();
        }
        DeviceResponse {
            documents: NonEmptyVec::maybe_new(
                self.signed_documents.into_iter().map(Into::into).collect(),
            ),
            status: Status::OK,
            version: "1.0".to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::issuance::mdoc::test::minimal_test_mdoc;
    use p256::ecdsa::Signature;
    use signature::Signer;

    #[test]
    fn respond() {
        let request = serde_json::Value::Null;

        let der = include_str!("../../../test/issuance/device_key.b64");
        let der_bytes = base64::decode(der).unwrap();
        let device_key: p256::ecdsa::SigningKey =
            p256::SecretKey::from_sec1_der(&der_bytes).unwrap().into();
        let mdoc = minimal_test_mdoc().expect("failed to issue new mdoc");
        let doc_type = mdoc.doc_type.clone();
        let documents = NonEmptyMap::new(doc_type, mdoc.into());

        // use std::io::Write;
        // let mut file = std::fs::File::create("mdoc_documents").unwrap();
        // file.write_all(&serde_cbor::to_vec(&documents).unwrap())
        //     .unwrap();

        //let device_jwk_str = r#"{
        //    "kty":"EC",
        //    "crv":"secp256k1",
        //    "x":"BoFNXJPrlLf7i7gxZ7OoNAujWUmJ7xkwOfA6kA8dlkk",
        //    "y":"nHXseRkDNFxWt2UpVDQL9Mu05WPAitJa5fCNdPU_M7g",
        //    "d":"ZXzavVc9F90aYQWm9kgrTjemOUdm88b1uU_g3VAm5CE"
        //}"#;
        //let device_jwk: ssi_jwk::JWK = serde_json::from_str(device_jwk_str).unwrap();
        let verifier_jwk_str = r#"{
            "use": "sig",
            "kty": "EC",
            "crv": "secp256k1",
            "d": "VTzcE-D-g5EFHcQ-73Qb599qK7X1oAliMu-4WmlnrJ4",
            "x": "HeNB-_4UDuDr8KlR-LGYHhKD3UTCbLWV9XrQg0iHfnQ",
            "y": "64g4jcby5TWR4LogR118SUumQ0TBUiJ-Tl6gMFCEXT0",
            "alg": "ES256K"
        }"#;
        let verifier_jwk: ssi_jwk::JWK = serde_json::from_str(verifier_jwk_str).unwrap();

        let manager = SessionManager::new(
            documents,
            "did:jwk:eyJ1c2UiOiAic2lnIiwgICJrdHkiOiAiRUMiLCAgImNydiI6ICJzZWNwMjU2azEiLCAgImQiOiAiVlR6Y0UtRC1nNUVGSGNRLTczUWI1OTlxSzdYMW9BbGlNdS00V21sbnJKNCIsIngiOiAiSGVOQi1fNFVEdURyOEtsUi1MR1lIaEtEM1VUQ2JMV1Y5WHJRZzBpSGZuUSIsICAieSI6ICI2NGc0amNieTVUV1I0TG9nUjExOFNVdW1RMFRCVWlKLVRsNmdNRkNFWFQwIiwiYWxnIjogIkVTMjU2SyIgfQ".to_string(),
            "nonce".to_string(),
            verifier_jwk,
            request,
        )
        .expect("failed to prepare response");

        let requested_items = manager.requested_items();

        // Ask for user permission. If they say yes, then:
        let permitted_items: super::super::PermittedItems = requested_items
            .clone()
            .into_iter()
            .map(|req| {
                let namespaces = req
                    .namespaces
                    .into_inner()
                    .into_iter()
                    .map(|(ns, es)| {
                        let ids = es.into_inner().into_keys().collect();
                        (ns, ids)
                    })
                    .collect();
                (req.doc_type, namespaces)
            })
            .collect();

        let mut prepared_response = manager.prepare_response(requested_items, permitted_items);

        while let Some((_, payload)) = prepared_response.get_next_signature_payload() {
            let signature: Signature = device_key.sign(payload);
            prepared_response.submit_next_signature(signature.to_bytes().to_vec());
        }
    }
}
