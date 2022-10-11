use crate::definitions::{
    helpers::{NonEmptyMap, NonEmptyVec},
    DeviceSigned, IssuerSigned,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    documents: Option<Documents>,
    #[serde(skip_serializing_if = "Option::is_none")]
    document_errors: Option<DocumentErrors>,
    status: Status,
}

pub type Documents = NonEmptyVec<Document>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    doc_type: String,
    issuer_signed: IssuerSigned,
    device_signed: DeviceSigned,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<Errors>,
}

pub type Errors = NonEmptyMap<String, NonEmptyMap<String, i128>>;

pub type DocumentErrors = NonEmptyVec<HashMap<String, i128>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub enum Status {
    OK,
    GeneralError,
    CborDecodingError,
    CborValidationError,
}

impl From<Status> for u64 {
    fn from(s: Status) -> u64 {
        match s {
            Status::OK => 0,
            Status::GeneralError => 10,
            Status::CborDecodingError => 11,
            Status::CborValidationError => 12,
        }
    }
}

impl TryFrom<u64> for Status {
    type Error = String;

    fn try_from(n: u64) -> Result<Status, String> {
        match n {
            0 => Ok(Status::OK),
            10 => Ok(Status::GeneralError),
            11 => Ok(Status::CborDecodingError),
            12 => Ok(Status::CborValidationError),
            _ => Err(format!("unrecognised error code: {n}")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::DeviceResponse;
    use hex::FromHex;

    static DEVICE_RESPONSE_CBOR: &str = include_str!("../../test/definitions/device_response.cbor");

    #[test]
    fn serde_device_response() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(DEVICE_RESPONSE_CBOR).expect("unable to convert cbor hex to bytes");
        let response: DeviceResponse =
            serde_cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as a DeviceResponse");
        let roundtripped_bytes =
            serde_cbor::to_vec(&response).expect("unable to encode DeviceResponse as cbor bytes");
        assert_eq!(
            cbor_bytes, roundtripped_bytes,
            "original cbor and re-serialized DeviceResponse do not match"
        );
    }
}
