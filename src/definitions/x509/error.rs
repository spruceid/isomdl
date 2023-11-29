use crate::definitions::device_key::cose_key::Error as CoseError;
use crate::definitions::helpers::non_empty_vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Error {
    ValidationError(String),
    DecodingError(String),
    CborDecodingError,
    JsonError,
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

impl From<x509_cert::der::Error> for Error {
    fn from(value: x509_cert::der::Error) -> Self {
        Error::ValidationError(value.to_string())
    }
}

impl From<p256::ecdsa::Error> for Error {
    fn from(value: p256::ecdsa::Error) -> Self {
        Error::ValidationError(value.to_string())
    }
}

impl From<x509_cert::spki::Error> for Error {
    fn from(value: x509_cert::spki::Error) -> Self {
        Error::ValidationError(value.to_string())
    }
}

impl From<CoseError> for Error {
    fn from(value: CoseError) -> Self {
        Error::ValidationError(value.to_string())
    }
}

impl From<non_empty_vec::Error> for Error {
    fn from(value: non_empty_vec::Error) -> Self {
        Error::ValidationError(value.to_string())
    }
}

impl From<asn1_rs::Error> for Error {
    fn from(value: asn1_rs::Error) -> Self {
        Error::ValidationError(value.to_string())
    }
}

// impl From<ecdsa::Error> for Error {
//     fn from(value: ecdsa::Error) -> Self {
//         Error::ValidationError(value.to_string())
//     }
// }
