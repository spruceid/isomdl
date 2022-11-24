use super::{DeviceSession, Documents, PreparedDeviceResponse};
use crate::definitions::{
    device_engagement::{DeviceEngagement, Security},
    device_request::{DocRequest, ItemsRequest},
    helpers::{NonEmptyMap, NonEmptyVec, Tag24},
    oid4vp::Document,
    session::{create_p256_ephemeral_keys, Handover, SessionTranscript},
};
use anyhow::Result;
use std::collections::HashMap;

pub struct SessionManager {
    documents: Documents,
    session_transcript: Tag24<SessionTranscript>,
}

impl DeviceSession for SessionManager {
    fn documents(&self) -> &Documents {
        &self.documents
    }

    fn session_transcript(&self) -> &Tag24<SessionTranscript> {
        &self.session_transcript
    }
}

impl SessionManager {
    pub fn prepare_oid4vp_response(
        documents: Documents,
        _request: serde_json::Value,
    ) -> Result<PreparedDeviceResponse> {
        let e_device_key = Tag24::new(create_p256_ephemeral_keys()?.1)?;
        let device_engagement = Tag24::new(DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, e_device_key),
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        })?;
        // TODO: Retrieve the EReaderKey from the request.
        let e_reader_key = Tag24::new(create_p256_ephemeral_keys()?.1)?;
        // TODO: Retrieve the aud and nonce from the request.
        let handover = Handover::OID4VP {
            aud: "hard-coded".into(),
            nonce: "example".into(),
        };
        let session_transcript =
            Tag24::new(SessionTranscript(device_engagement, e_reader_key, handover))?;
        let manager = SessionManager {
            documents,
            session_transcript,
        };

        // TODO: Handle the document requests. For now we assume all data from all documents are
        // being requested, with no intent to retain.
        let doc_requests: NonEmptyVec<DocRequest> = manager
            .documents
            .as_ref()
            .values()
            .map(request_all)
            .collect::<Result<Vec<DocRequest>>>()?
            .try_into()
            // Safe to unwrap as documents is initially a NonEmptyVec, so has at least one element.
            .unwrap();

        Ok(manager.prepare_response(doc_requests))
    }
}

/// Build a DocRequest for a Document for all data elements with no intent to retain.
fn request_all(document: &super::Document) -> Result<DocRequest> {
    let namespaces = document
        .namespaces
        .as_ref()
        .iter()
        .map(|(ns, elems)| {
            let elems: NonEmptyMap<String, bool> = elems
                .as_ref()
                .iter()
                .map(|(elem, _)| (elem.clone(), false))
                .collect::<HashMap<String, bool>>()
                .try_into()
                // Safe to unwrap as elems is initially a NonEmptyMap, so has at least one element.
                .unwrap();
            (ns.clone(), elems)
        })
        .collect::<HashMap<String, NonEmptyMap<String, bool>>>()
        .try_into()
        // Safe to unwrap as namespaces is initially a NonEmptyMap, so has at least one element.
        .unwrap();
    let items_request = ItemsRequest {
        doc_type: document.mso.doc_type.clone(),
        request_info: None,
        namespaces,
    };
    Ok(DocRequest {
        reader_auth: None,
        items_request: Tag24::new(items_request)?,
    })
}

impl PreparedDeviceResponse {
    pub fn finalize_oid4vp_response(self) -> Vec<Document> {
        if !self.is_complete() {
            tracing::warn!("attempt to finalize PreparedDeviceResponse before all prepared documents had been authorized");
            return PreparedDeviceResponse::empty(super::Status::GeneralError)
                .finalize_oid4vp_response();
        }
        self.signed_documents.into_iter().map(Into::into).collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::issuance::mdoc::test::minimal_test_mdoc;
    use crate::presentation::Stringify;
    use signature::{Signature, Signer};

    #[test]
    fn respond() {
        let request = serde_json::Value::Null;

        let der = include_str!("../../../test/issuance/device_key.b64");
        let der_bytes = base64::decode(der).unwrap();
        let device_key: p256::ecdsa::SigningKey =
            p256::SecretKey::from_sec1_der(&der_bytes).unwrap().into();
        let mdoc = minimal_test_mdoc().expect("failed to issue new mdoc");
        let doc_type = mdoc.doc_type.clone();

        let mut prepared_response = SessionManager::prepare_oid4vp_response(
            NonEmptyMap::new(doc_type, mdoc.into()),
            request,
        )
        .expect("failed to prepare response");

        while let Some((_, payload)) = prepared_response.get_next_signature_payload() {
            let signature = device_key.sign(payload);
            prepared_response.submit_next_signature(signature.as_bytes().to_vec());
        }

        let _documents: Vec<String> = prepared_response
            .finalize_oid4vp_response()
            .iter()
            .map(Stringify::stringify)
            .collect::<Result<_, _>>()
            .unwrap();

        // Record generated response:
        // use std::io::Write;
        // let mut file = std::fs::File::create("vp_token").unwrap();
        // file.write_all(_documents[0].as_bytes()).unwrap()
    }
}
