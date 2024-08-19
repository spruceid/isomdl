use std::collections::BTreeMap;

use ciborium::Value;
use coset::{iana, AsCborValue};
use serde::{Deserialize, Serialize};
use crate::cose::sign1::CoseSign1;
use crate::definitions::{
    helpers::{NonEmptyMap, NonEmptyVec},
    DeviceSigned, IssuerSigned,
};

/// Represents a device response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    /// The version of the response.
    pub version: String,

    /// The documents associated with the response, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Documents>,

    /// The errors associated with the documents, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_errors: Option<DocumentErrors>,

    /// The status of the response.
    pub status: Status,
}

pub type Documents = NonEmptyVec<Document>;

fn to_cbor_value(docs: Documents) -> coset::Result<Value> {
    docs.into_iter().map(|s| s.)
    Ok(t.to_cbor_value()?)
}

/// Represents a document.
///
/// This struct is used to store information about a document.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// A string representing the type of the document.
    pub doc_type: String,

    /// An instance of the [IssuerSigned] struct representing the issuer-signed data.
    pub issuer_signed: IssuerSigned,

    /// An instance of the [DeviceSigned] struct representing the device-signed data.
    pub device_signed: DeviceSigned,

    /// An optional instance of the [Errors] struct representing any errors associated with the document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Errors>,
}

impl coset::CborSerializable for Document {}
impl AsCborValue for Document {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        todo!()
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        todo!()
    }
}


/// Errors mapped by namespace and element identifier.
pub type Errors = NonEmptyMap<String, NonEmptyMap<String, DocumentErrorCode>>;
/// A list of document errors.
pub type DocumentErrors = NonEmptyVec<DocumentError>;
/// A map of document type to document error for them.
pub type DocumentError = BTreeMap<String, DocumentErrorCode>;

/// Document specific errors.
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

impl coset::CborSerializable for DeviceResponse {}
impl AsCborValue for DeviceResponse {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        if let Value::Tag(tag, value) = value {
            if tag != iana::CborTag::CoseSign1 as u64 {
                return Err(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "unexpected tag".to_string()),
                ));
            }
            Ok(CoseSign1 {
                tagged: true,
                inner: coset::CoseSign1::from_cbor_value(*value)?,
            })
        } else {
            Ok(CoseSign1 {
                tagged: false,
                inner: coset::CoseSign1::from_cbor_value(value)?,
            })
        }
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Array(vec![
            self.documents.cbor_bstr()?,
            self.unprotected.to_cbor_value()?,
            match self.payload {
                Some(b) => Value::Bytes(b),
                None => Value::Null,
            },
            Value::Bytes(self.signature),
        ]))

        if self.tagged {
            Ok(Value::Tag(
                iana::CborTag::CoseSign1 as u64,
                Box::new(self.inner.to_cbor_value()?),
            ))
        } else {
            Ok(self.inner.to_cbor_value()?)
        }
    }
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
