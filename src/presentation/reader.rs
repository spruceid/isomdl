use crate::definitions::{
    device_engagement::DeviceRetrievalMethod,
    device_request::{self, DeviceRequest, DocRequest, ItemsRequest},
    helpers::{NonEmptyVec, Tag24},
    session::{
        self, create_p256_ephemeral_keys, derive_session_key, get_shared_secret, Handover,
        SessionEstablishment,
    },
    DeviceEngagement, DeviceResponse, SessionData, SessionTranscript,
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;
// TODO: Consider removing serde derivations down the line as Tag24 does not round-trip with
// non-cbor serde implementors.
#[derive(Serialize, Deserialize)]
pub struct SessionManager {
    session_transcript: Tag24<SessionTranscript>,
    sk_device: [u8; 32],
    device_message_counter: u32,
    sk_reader: [u8; 32],
    reader_message_counter: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the qr code had the wrong prefix or the contained data could not be decoded: {0}")]
    InvalidQrCode(anyhow::Error),
    #[error("Device did not transmit any data.")]
    DeviceTransmissionError,
    #[error("Device did not transmit an mDL.")]
    DocumentTypeError,
    #[error("the device did not transmit any mDL data.")]
    NoMdlDataTransmission,
    #[error("device did not transmit any data in the org.iso.18013.5.1 namespace.")]
    IncorrectNamespace,
    #[error("device responded with an error.")]
    HolderError,
    #[error("could not decrypt the response.")]
    DecryptionError,
    #[error("Unexpected CBOR type for offered value")]
    CborDecodingError,
    #[error("not a valid JSON input.")]
    JsonError,
    #[error("Unexpected date type for data_element.")]
    ParsingError,
}

impl From<serde_cbor::Error> for Error {
    fn from(_: serde_cbor::Error) -> Self {
        Error::CborDecodingError
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::JsonError
    }
}

// TODO: Refactor for more general implementation. This implementation will work for a simple test
// reader application, but it is not at all configurable.
impl SessionManager {
    pub fn establish_session(
        qr_code: String,
        namespaces: device_request::Namespaces,
    ) -> Result<(Self, Vec<u8>, [u8; 16])> {
        let device_engagement_bytes =
            Tag24::<DeviceEngagement>::from_qr_code_uri(&qr_code).map_err(Error::InvalidQrCode)?;

        //generate own keys
        let key_pair = create_p256_ephemeral_keys()?;
        let e_reader_key_private = key_pair.0;
        let e_reader_key_public = Tag24::new(key_pair.1)?;

        //decode device_engagement
        let device_engagement = device_engagement_bytes.as_ref();
        let e_device_key = &device_engagement.security.1;

        // calculate ble Ident value
        let ble_ident = super::calculate_ble_ident(e_device_key)?;

        // derive shared secret
        let shared_secret = get_shared_secret(
            e_device_key.clone().into_inner(),
            &e_reader_key_private.into(),
        )?;

        let session_transcript = Tag24::new(SessionTranscript(
            device_engagement_bytes,
            e_reader_key_public.clone(),
            // TODO: Support NFC handover.
            Handover::QR,
        ))?;

        //derive session keys
        let sk_reader = derive_session_key(&shared_secret, &session_transcript, true)?.into();
        let sk_device = derive_session_key(&shared_secret, &session_transcript, false)?.into();

        let mut session_manager = Self {
            session_transcript,
            sk_device,
            device_message_counter: 0,
            sk_reader,
            reader_message_counter: 0,
        };

        let request = session_manager.build_request(namespaces)?;
        let session = SessionEstablishment {
            data: request.into(),
            e_reader_key: e_reader_key_public,
        };
        let session_request = serde_cbor::to_vec(&session)?;

        Ok((session_manager, session_request, ble_ident))
    }

    pub fn first_central_client_uuid(&self) -> Option<&Uuid> {
        self.session_transcript
            .as_ref()
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

    pub fn new_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        let request = self.build_request(namespaces)?;
        let session = SessionData {
            data: Some(request.into()),
            status: None,
        };
        serde_cbor::to_vec(&session).map_err(Into::into)
    }

    // TODO: Support requesting specific doc types.
    fn build_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        let items_request = ItemsRequest {
            doc_type: "org.iso.18013.5.1.mDL".into(),
            namespaces,
            request_info: None,
        };
        let doc_request = DocRequest {
            // TODO: implement reader auth.
            reader_auth: None,
            items_request: Tag24::new(items_request)?,
        };
        let device_request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(doc_request),
        };
        let device_request_bytes = serde_cbor::to_vec(&device_request)?;
        session::encrypt_reader_data(
            &self.sk_reader.into(),
            &device_request_bytes,
            &mut self.reader_message_counter,
        )
        .map_err(|e| anyhow!("unable to encrypt request: {}", e))
    }

    // TODO: Handle any doc type.
    pub fn handle_response(&mut self, response: &[u8]) -> Result<BTreeMap<String, Value>, Error> {
        let session_data: SessionData = serde_cbor::from_slice(response)?;
        let encrypted_response = match session_data.data {
            None => return Err(Error::HolderError),
            Some(r) => r,
        };
        // TODO: Handle case where session termination status code is returned with data.
        let decrypted_response = session::decrypt_device_data(
            &self.sk_device.into(),
            encrypted_response.as_ref(),
            &mut self.device_message_counter,
        )
        .map_err(|_e| Error::DecryptionError)?;
        let response: DeviceResponse = serde_cbor::from_slice(&decrypted_response)?;
        // TODO: Mdoc authentication.
        //
        // 1. As part of mdoc response, mdl produces `DeviceAuth`, which is either a `DeviceSignature` or
        //    a `DeviceMac`.
        //
        // 2. The reader must verify that `DeviceKey` in the MSO is the key that generated the
        //    `DeviceAuth`.
        //
        // 3. The reader must verify that the `DeviceKey` is authorized by `KeyAuthorizations` to
        //    sign over the data elements present in `DeviceNameSpaces`.
        //
        // 4. The reader must verify that the `DeviceKey` is the subject of the x5chain, and that the
        //    x5chain is consistent and issued by a trusted source.
        let mut parsed_response = BTreeMap::<String, serde_json::Value>::new();
        response
            .documents
            .ok_or(Error::DeviceTransmissionError)?
            .into_inner()
            .into_iter()
            .find(|doc| doc.doc_type == "org.iso.18013.5.1.mDL")
            .ok_or(Error::DocumentTypeError)?
            .issuer_signed
            .namespaces
            .ok_or(Error::NoMdlDataTransmission)?
            .into_inner()
            .remove("org.iso.18013.5.1")
            .ok_or(Error::IncorrectNamespace)?
            .into_inner()
            .into_iter()
            .map(|item| item.into_inner())
            .for_each(|item| {
                let value = parse_response(item.element_value.clone());
                if let Ok(val) = value {
                    parsed_response.insert(item.element_identifier, val);
                }
            });
        Ok(parsed_response)
    }
}

fn parse_response(value: CborValue) -> Result<Value, Error> {
    match value {
        CborValue::Text(s) => Ok(Value::String(s)),
        CborValue::Tag(_t, v) => {
            if let CborValue::Text(d) = *v {
                Ok(Value::String(d))
            } else {
                Err(Error::ParsingError)
            }
        }
        CborValue::Array(v) => {
            let mut array_response = Vec::<Value>::new();
            for a in v {
                let r = parse_response(a)?;
                array_response.push(r);
            }
            Ok(json!(array_response))
        }
        CborValue::Map(m) => {
            let mut map_response = BTreeMap::<String, String>::new();
            for (key, value) in m {
                if let CborValue::Text(k) = key {
                    let parsed = parse_response(value)?;
                    if let Value::String(x) = parsed {
                        map_response.insert(k, x);
                    }
                }
            }
            let json = json!(map_response);
            Ok(json)
        }
        CborValue::Bytes(b) => Ok(json!(b)),
        CborValue::Bool(b) => Ok(json!(b)),
        CborValue::Integer(i) => Ok(json!(i)),
        _ => Err(Error::ParsingError),
    }
}
