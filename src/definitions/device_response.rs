//! This module contains the definition of the `DeviceResponse` struct and related types.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
    use crate::cbor;
    use crate::cose::MaybeTagged;
    use crate::definitions::device_signed::{
        DeviceNamespaces, DeviceNamespacesBytes, DeviceSignedItems,
    };
    use crate::definitions::helpers::NonEmptyVec;
    use crate::definitions::issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes};
    use crate::definitions::{
        DeviceAuth, DeviceSigned, DigestId, Document, IssuerSigned, IssuerSignedItem,
    };
    use coset::{CoseMac0, CoseSign1};
    use hex::FromHex;

    use super::{
        DeviceResponse, DocumentError, DocumentErrorCode, DocumentErrors, Documents, Status,
    };

    static DEVICE_RESPONSE_CBOR: &str = include_str!("../../test/definitions/device_response.cbor");

    #[test]
    fn device_response() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(DEVICE_RESPONSE_CBOR).expect("unable to convert cbor hex to bytes");
        let response: DeviceResponse =
            cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as a DeviceResponse");
        let roundtripped_bytes =
            cbor::to_vec(&response).expect("unable to encode DeviceResponse as cbor bytes");
        assert_eq!(
            cbor_bytes, roundtripped_bytes,
            "original cbor and re-serialized DeviceResponse do not match"
        );
    }

    #[test]
    fn device_response_roundtrip() {
        static COSE_SIGN1: &str = include_str!("../../test/definitions/cose/sign1/serialized.cbor");
        static COSE_MAC0: &str = include_str!("../../test/definitions/cose/mac0/serialized.cbor");

        let bytes = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        let cose_sign1: MaybeTagged<CoseSign1> =
            cbor::from_slice(&bytes).expect("failed to parse COSE_Sign1 from bytes");
        let bytes = Vec::<u8>::from_hex(COSE_MAC0).unwrap();
        let cose_mac0: MaybeTagged<CoseMac0> =
            cbor::from_slice(&bytes).expect("failed to parse COSE_MAC0 from bytes");

        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId::new(42),
            random: vec![42_u8].into(),
            element_identifier: "42".to_string(),
            element_value: ciborium::Value::Null,
        };
        let issuer_signed_item_bytes = IssuerSignedItemBytes::new(issuer_signed_item).unwrap();
        let vec = NonEmptyVec::new(issuer_signed_item_bytes);
        let issuer_namespaces = IssuerNamespaces::new("a".to_string(), vec);
        let device_signed_items = DeviceSignedItems::new("a".to_string(), ciborium::Value::Null);
        let mut device_namespaces = DeviceNamespaces::new();
        device_namespaces.insert("a".to_string(), device_signed_items);
        let device_namespaces_bytes = DeviceNamespacesBytes::new(device_namespaces).unwrap();
        let doc = Document {
            doc_type: "aaa".to_string(),
            issuer_signed: IssuerSigned {
                namespaces: Some(issuer_namespaces),
                issuer_auth: cose_sign1.clone(),
            },
            device_signed: DeviceSigned {
                namespaces: device_namespaces_bytes,
                device_auth: DeviceAuth::DeviceMac(cose_mac0),
            },
            errors: None,
        };
        let docs = Documents::new(doc);
        let document_error_code = DocumentErrorCode::DataNotReturned;
        let mut error = DocumentError::new();
        error.insert("a".to_string(), document_error_code);
        let errors = DocumentErrors::new(error);
        let res = DeviceResponse {
            version: "1.0".to_string(),
            documents: Some(docs),
            document_errors: Some(errors),
            status: Status::OK,
        };
        let bytes = cbor::to_vec(&res).unwrap();
        let res: DeviceResponse = cbor::from_slice(&bytes).unwrap();
        let roundtripped_bytes = cbor::to_vec(&res).unwrap();
        assert_eq!(
            bytes, roundtripped_bytes,
            "original cbor and re-serialized DeviceResponse do not match"
        );
    }
}
