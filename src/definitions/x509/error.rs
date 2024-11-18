use crate::definitions::device_key::cose_key::Error as CoseError;
use crate::definitions::helpers::non_empty_vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, thiserror::Error)]
pub enum Error {
    #[error("Error occurred while validating x509 certificate: {0}")]
    ValidationError(String),
    #[error("Error occurred while decoding a x509 certificate: {0}")]
    DecodingError(String),
    #[error("Error decoding cbor")]
    CborDecodingError,
    #[error("Error decoding json")]
    JsonError,
    #[error("Custom Trust Anchor Not Implemented: {0}")]
    CustomTrustAnchorNotImplemented(String),
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
