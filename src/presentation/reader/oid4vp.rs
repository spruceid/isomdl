use crate::definitions::{
    device_request::{self},
    oid4vp::DeviceResponse
};
use anyhow::{Result};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
// TODO: Consider removing serde derivations down the line as Tag24 does not round-trip with
// non-cbor serde implementors.
#[derive(Serialize, Deserialize)]
pub struct SessionManager {
    device_response: DeviceResponse,
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
    #[error("Request for data is invalid.")]
    InvalidRequest,
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
    pub fn new(device_response: DeviceResponse) -> Result<Self, Error> {
        Ok(SessionManager{device_response})
    }

    // pub fn new_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
    //     let request = self.build_request(namespaces)?;
    //     let session = SessionData {
    //         data: Some(request.into()),
    //         status: None,
    //     };
    //     serde_cbor::to_vec(&session).map_err(Into::into)
    // }

    // TODO: Support requesting specific doc types.
    // fn build_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
    //     //TODO: Validate Request and determine behaviour for invalid requests
    //     // if !validate_request(namespaces.clone()).is_ok() {
    //     //     return Err(anyhow::Error::msg(
    //     //         "At least one of the namespaces contain an invalid combination of fields to request",
    //     //     ));
    //     // }
    //     let items_request = ItemsRequest {
    //         doc_type: "org.iso.18013.5.1.mDL".into(),
    //         namespaces,
    //         request_info: None,
    //     };
    //     let doc_request = DocRequest {
    //         // TODO: implement reader auth.
    //         reader_auth: None,
    //         items_request: Tag24::new(items_request)?,
    //     };
    //     let device_request = DeviceRequest {
    //         version: DeviceRequest::VERSION.to_string(),
    //         doc_requests: NonEmptyVec::new(doc_request),
    //     };
    //     let device_request_bytes = serde_cbor::to_vec(&device_request)?;
    //     session::encrypt_reader_data(
    //         &self.sk_reader.into(),
    //         &device_request_bytes,
    //         &mut self.reader_message_counter,
    //     )
    //     .map_err(|e| anyhow!("unable to encrypt request: {}", e))
    // }

    // TODO: Handle any doc type.
    pub fn handle_response(&mut self) -> Result<BTreeMap<String, Value>, Error> {

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
        let response = self.device_response.clone();
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

fn _validate_request(namespaces: device_request::Namespaces) -> Result<bool, Error> {
    // Check if request follows ISO18013-5 restrictions
    // A valid mdoc request can contain a maximum of 2 age_over_NN fields
    let age_over_nn_requested: Vec<(String, bool)> = namespaces
        .get("org.iso.18013.5.1")
        .map(|k| k.clone().into_inner())
        //To Do: get rid of unwrap
        .unwrap()
        .into_iter()
        .filter(|x| x.0.contains("age_over"))
        .collect();

    if age_over_nn_requested.len() > 2 {
        //To Do: Decide what should happen when more than two age_over_nn are requested
        return Err(Error::InvalidRequest);
    }

    Ok(true)
}
