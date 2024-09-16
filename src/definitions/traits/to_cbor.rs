//! ToCbor is specifically NOT implemented for `Vec<T>` where `T: ToCbor`, as `Vec<u8>` likely should be
//! represented as a `bytestr` instead of an `array` in `cbor`.

use crate::cbor;
use crate::cbor::CborError;
use std::collections::BTreeMap;

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

#[derive(Debug, thiserror::Error)]
pub enum ToCborError {
    #[error("cbor error: {0}")]
    CoseError(#[from] CborError),
}

impl<T> ToCbor for T
where
    T: Into<ciborium::Value>,
{
    fn to_cbor(self) -> ciborium::Value {
        self.into()
    }
}
