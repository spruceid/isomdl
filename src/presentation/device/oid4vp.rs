use super::{DeviceSession, Documents, PreparedDeviceResponse, RequestedItems};
use crate::definitions::{
    device_engagement::{DeviceEngagement, Security},
    device_request::{ItemsRequest},
    device_response::Status,
    helpers::{NonEmptyMap, NonEmptyVec, Tag24},
    oid4vp::DeviceResponse,
    session::{Handover, SessionTranscript},
    CoseKey,
};
use anyhow::Result;
use std::collections::HashMap;

pub struct SessionManager {
    documents: Documents,
    session_transcript: Tag24<SessionTranscript>,
    requested_items: RequestedItems,
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
    pub fn new<K1, K2>(
        documents: Documents,
        aud: String,
        nonce: String,
        e_device_key: K1,
        e_verifier_key: K2,
        _request: serde_json::Value,
    ) -> Result<Self>
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

        // TODO: Handle the document requests. For now we assume all data from all documents are
        // being requested, with no intent to retain.
        let requested_items = documents
            .as_ref()
            .values()
            .map(request_all)
            .collect::<Result<_,_>>()?;

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
        let documents = NonEmptyMap::new(doc_type, mdoc.into());

        use std::io::Write;
        let mut file = std::fs::File::create("mdoc_documents").unwrap();
        file.write_all(&serde_cbor::to_vec(&documents).unwrap())
            .unwrap();

        let device_jwk_str = r#"{
            "kty":"EC",
            "crv":"secp256k1",
            "x":"BoFNXJPrlLf7i7gxZ7OoNAujWUmJ7xkwOfA6kA8dlkk",
            "y":"nHXseRkDNFxWt2UpVDQL9Mu05WPAitJa5fCNdPU_M7g",
            "d":"ZXzavVc9F90aYQWm9kgrTjemOUdm88b1uU_g3VAm5CE"
        }"#;
        let device_jwk: ssi_jwk::JWK = serde_json::from_str(device_jwk_str).unwrap();
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
            device_jwk,
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
            let signature = device_key.sign(payload);
            prepared_response.submit_next_signature(signature.as_bytes().to_vec());
        }

        let _documents: String = serde_cbor::to_vec(&prepared_response.finalize_oid4vp_response())
            .map(|docs| base64::encode_config(&docs, base64::URL_SAFE_NO_PAD))
            .unwrap();

        // Record generated response:
        // use std::io::Write;
        // let mut file = std::fs::File::create("vp_token").unwrap();
        // file.write_all(_documents[0].as_bytes()).unwrap()
    }
}
