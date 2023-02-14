//! ToCbor is specifically NOT implemented for Vec<T> where T: ToCbor, as Vec<u8> likely should be
//! represented as a bytestr instead of an array in cbor.

use serde_cbor::Value;
use std::collections::BTreeMap;

pub type Bytes = Vec<u8>;

pub trait ToCbor: Sized {
    fn to_cbor(self) -> Value;
    fn to_cbor_bytes(self) -> Result<Bytes, ToCborError> {
        serde_cbor::to_vec(&self.to_cbor()).map_err(Into::into)
    }
}

pub trait ToCborMap {
    fn to_map(self) -> BTreeMap<Value, Value>;
}

#[derive(Debug, thiserror::Error)]
pub enum ToCborError {
    #[error("cbor serialization: {0}")]
    Serde(#[from] serde_cbor::Error)
}

impl<T> ToCbor for T 
where
    T: Into<Value>
{
    fn to_cbor(self) -> Value {
        self.into()
    }
}

impl<K, V> ToCborMap for BTreeMap<K,V>
where
    K: ToCbor,
    V: ToCbor
{
    fn to_map(self) -> BTreeMap<Value, Value> {
        self.into_iter()
            .map(|(k,v)| (k.to_cbor(), v.to_cbor()))
            .collect()
    }
}
