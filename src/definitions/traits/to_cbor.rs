//! ToCbor is specifically NOT implemented for `Vec<T>` where `T: ToCbor`, as `Vec<u8>` likely should be
//! represented as a `bytestr` instead of an `array` in `cbor`.

use crate::cbor;
use crate::cbor::CborError;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

pub type Bytes = Vec<u8>;

pub trait ToCbor: Sized {
    fn to_cbor(self) -> ciborium::Value;
    fn to_cbor_bytes(self) -> Result<Bytes, ToCborError> {
        cbor::to_vec(&self.to_cbor()).map_err(Into::into)
    }
}

pub trait ToCborMap {
    fn to_cbor_map(self) -> BTreeMap<ciborium::Value, ciborium::Value>;
}

pub trait ToNamespaceMap {
    fn to_ns_map(self) -> BTreeMap<String, ciborium::Value>;
}

// Define your error enum with just the CoseError variant
#[derive(Debug)]
pub enum ToCborError {
    CborError(CborError),
}

// Implement Display for ToCborError
impl fmt::Display for ToCborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToCborError::CborError(err) => write!(f, "COSE error: {}", err),
        }
    }
}

// Implement Error for ToCborError
impl Error for ToCborError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ToCborError::CborError(err) => Some(err),
        }
    }
}

// Implement From<CoseError> to easily convert CoseError into ToCborError
impl From<CborError> for ToCborError {
    fn from(err: CborError) -> ToCborError {
        ToCborError::CborError(err)
    }
}

impl<T> ToCbor for T
where
    T: Into<ciborium::Value>,
{
    fn to_cbor(self) -> ciborium::Value {
        self.into()
    }
}
