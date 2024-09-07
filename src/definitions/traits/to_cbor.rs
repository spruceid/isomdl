//! ToCbor is specifically NOT implemented for `Vec<T>` where `T: ToCbor`, as `Vec<u8>` likely should be
//! represented as a `bytestr` instead of an `array` in `cbor`.

use crate::cbor;
use crate::cbor::{CborError, Value};
use std::collections::BTreeMap;

pub type Bytes = Vec<u8>;

pub trait ToCbor: Sized {
    fn to_cbor(self) -> Value;
    fn to_cbor_bytes(self) -> Result<Bytes, ToCborError> {
        cbor::to_vec(&self.to_cbor().0).map_err(Into::into)
    }
}

pub trait ToCborMap {
    fn to_cbor_map(self) -> BTreeMap<Value, Value>;
}

pub trait ToNamespaceMap {
    fn to_ns_map(self) -> BTreeMap<String, Value>;
}

#[derive(Debug, thiserror::Error)]
pub enum ToCborError {
    #[error("cbor error: {0}")]
    CoseError(#[from] CborError),
}

impl<T> ToCbor for T
where
    T: Into<Value>,
{
    fn to_cbor(self) -> Value {
        self.into()
    }
}

impl ToCbor for Option<String> {
    fn to_cbor(self) -> Value {
        self.map(|s| ciborium::Value::Text(s).into())
            .unwrap_or_else(|| ciborium::Value::Null.into())
    }
}
