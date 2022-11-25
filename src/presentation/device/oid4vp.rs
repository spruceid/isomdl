use super::{DeviceSession, Documents, PreparedDeviceResponse};
use crate::definitions::{
    device_engagement::{DeviceEngagement, Security},
    device_request::{DocRequest, ItemsRequest},
    helpers::{NonEmptyMap, NonEmptyVec, Tag24},
    oid4vp::Document,
    session::{Handover, SessionTranscript},
    CoseKey,
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
    pub fn prepare_oid4vp_response<K1, K2>(
        documents: Documents,
        aud: String,
        nonce: String,
        e_device_key: K1,
        e_verifier_key: K2,
        _request: serde_json::Value,
    ) -> Result<PreparedDeviceResponse>
    where
        K1: TryInto<CoseKey>,
        <K1 as TryInto<CoseKey>>::Error: Sync + Send + std::error::Error + 'static,
        K2: TryInto<CoseKey>,
        <K2 as TryInto<CoseKey>>::Error: Sync + Send + std::error::Error + 'static,
    {
        let e_device_key = Tag24::new(e_device_key.try_into()?)?;
        let device_engagement = Tag24::new(DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, e_device_key),
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        })?;
        let e_reader_key = Tag24::new(e_verifier_key.try_into()?)?;
        let handover = Handover::OID4VP { aud, nonce };
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

        let jwk_str = r#"{"use": "sig",  "kty": "EC",  "crv": "secp256k1",  "d": "VTzcE-D-g5EFHcQ-73Qb599qK7X1oAliMu-4WmlnrJ4","x": "HeNB-_4UDuDr8KlR-LGYHhKD3UTCbLWV9XrQg0iHfnQ",  "y": "64g4jcby5TWR4LogR118SUumQ0TBUiJ-Tl6gMFCEXT0","alg": "ES256K" }"#;
        let jwk: ssi_jwk::JWK = serde_json::from_str(jwk_str).unwrap();

        let mut prepared_response = SessionManager::prepare_oid4vp_response(
            NonEmptyMap::new(doc_type, mdoc.into()),
            "aud".to_string(),
            "nonce".to_string(),
            jwk.clone(),
            jwk,
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
