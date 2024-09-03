//! ToCbor is specifically NOT implemented for `Vec<T>` where `T: ToCbor`, as `Vec<u8>` likely should be
//! represented as a `bytestr` instead of an `array` in `cbor`.

use crate::cbor::CborValue;
use std::collections::BTreeMap;

pub type Bytes = Vec<u8>;

pub trait ToCbor: Sized {
    fn to_cbor(self) -> CborValue;
    fn to_cbor_bytes(self) -> Result<Bytes, ToCborError> {
        coset::CborSerializable::to_vec(self.to_cbor()).map_err(Into::into)
    }
}

pub trait ToCborMap {
    fn to_cbor_map(self) -> BTreeMap<CborValue, CborValue>;
}

pub trait ToNamespaceMap {
    fn to_ns_map(self) -> BTreeMap<String, CborValue>;
}

#[derive(Debug, thiserror::Error)]
pub enum ToCborError {
    #[error("cbor serialization: {0}")]
    Serde(#[from] coset::CoseError),
}

impl<T> ToCbor for T
where
    T: Into<CborValue>,
{
    fn to_cbor(self) -> CborValue {
        self.into()
    }
}
