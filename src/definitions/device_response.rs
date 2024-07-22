use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::definitions::{
    helpers::{NonEmptyMap, NonEmptyVec},
    DeviceSigned, IssuerSigned,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Documents>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_errors: Option<DocumentErrors>,
    pub status: Status,
}

pub type Documents = NonEmptyVec<Document>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub doc_type: String,
    pub issuer_signed: IssuerSigned,
    pub device_signed: DeviceSigned,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Errors>,
}

pub type Errors = NonEmptyMap<String, NonEmptyMap<String, DocumentErrorCode>>;
pub type DocumentErrors = NonEmptyVec<DocumentError>;
pub type DocumentError = BTreeMap<String, DocumentErrorCode>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "i128", into = "i128")]
pub enum DocumentErrorCode {
    DataNotReturned,
    ApplicationSpecific(i128),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub enum Status {
    OK,
    GeneralError,
    CborDecodingError,
    CborValidationError,
}

impl DeviceResponse {
    pub const VERSION: &'static str = "1.0";
}

impl From<DocumentErrorCode> for i128 {
    fn from(c: DocumentErrorCode) -> i128 {
        match c {
            DocumentErrorCode::DataNotReturned => 0,
            DocumentErrorCode::ApplicationSpecific(i) => i,
        }
    }
}

impl TryFrom<i128> for DocumentErrorCode {
    type Error = String;

    fn try_from(n: i128) -> Result<DocumentErrorCode, String> {
        match n {
            0 => Ok(DocumentErrorCode::DataNotReturned),
            i if i < 0 => Ok(DocumentErrorCode::ApplicationSpecific(i)),
            _ => Err(format!("unsupported or RFU error code used: {n}")),
        }
    }
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
    use hex::FromHex;

    use super::DeviceResponse;

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
