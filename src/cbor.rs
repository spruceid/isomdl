use std::io::Cursor;

use ciborium::Value;
use coset::{cbor, CoseError, EndOfFile};
use serde::{de, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CborError {
    /// CBOR decoding failure.
    #[error("CBOR decoding failure: {0}")]
    DecodeFailed(cbor::de::Error<EndOfFile>),
    /// Duplicate map key detected.
    #[error("duplicate map key")]
    DuplicateMapKey,
    /// CBOR encoding failure.
    #[error("CBOR encoding failure")]
    EncodeFailed,
    /// CBOR input had extra data.
    #[error("extraneous data")]
    ExtraneousData,
    /// Integer value on the wire is outside the range of integers representable in this crate.
    /// See <https://crates.io/crates/coset/#integer-ranges>.
    #[error("integer value out of range")]
    OutOfRangeIntegerValue,
    /// Unexpected CBOR item encountered (got, want).
    #[error("unexpected item: {0}, want {1}")]
    UnexpectedItem(&'static str, &'static str),
    /// Unrecognized value in IANA-controlled range (with no private range).
    #[error("unregistered IANA value")]
    UnregisteredIanaValue,
    /// Unrecognized value in neither IANA-controlled range nor private range.
    #[error("unregistered non-private IANA value")]
    UnregisteredIanaNonPrivateValue,
    /// Value contains non-finite float (NaN or Infinity).
    #[error("non finite floats")]
    NonFiniteFloats,
}

impl PartialEq for CborError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::DecodeFailed(_), Self::DecodeFailed(_)) => true,
            (Self::DuplicateMapKey, Self::DuplicateMapKey) => true,
            (Self::EncodeFailed, Self::EncodeFailed) => true,
            (Self::ExtraneousData, Self::ExtraneousData) => true,
            (Self::OutOfRangeIntegerValue, Self::OutOfRangeIntegerValue) => true,
            (Self::UnexpectedItem(l_msg, l_want), Self::UnexpectedItem(r_msg, r_want)) => {
                l_msg == r_msg && l_want == r_want
            }
            (Self::UnregisteredIanaValue, Self::UnregisteredIanaValue) => true,
            (Self::UnregisteredIanaNonPrivateValue, Self::UnregisteredIanaNonPrivateValue) => true,
            (Self::NonFiniteFloats, Self::NonFiniteFloats) => true,
            _ => false,
        }
    }
}

impl Eq for CborError {}

impl Clone for CborError {
    fn clone(&self) -> Self {
        match self {
            CborError::DecodeFailed(_) => panic!("cannot clone"),
            CborError::DuplicateMapKey => CborError::DuplicateMapKey,
            CborError::EncodeFailed => CborError::EncodeFailed,
            CborError::ExtraneousData => CborError::ExtraneousData,
            CborError::OutOfRangeIntegerValue => CborError::OutOfRangeIntegerValue,
            CborError::UnexpectedItem(msg, want) => CborError::UnexpectedItem(msg, want),
            CborError::UnregisteredIanaValue => CborError::UnregisteredIanaValue,
            CborError::UnregisteredIanaNonPrivateValue => {
                CborError::UnregisteredIanaNonPrivateValue
            }
            CborError::NonFiniteFloats => CborError::NonFiniteFloats,
        }
    }
}

impl From<CoseError> for CborError {
    fn from(e: CoseError) -> Self {
        match e {
            CoseError::DecodeFailed(e) => CborError::DecodeFailed(e),
            CoseError::DuplicateMapKey => CborError::DuplicateMapKey,
            CoseError::EncodeFailed => CborError::EncodeFailed,
            CoseError::ExtraneousData => CborError::ExtraneousData,
            CoseError::OutOfRangeIntegerValue => CborError::OutOfRangeIntegerValue,
            CoseError::UnexpectedItem(s, s2) => CborError::UnexpectedItem(s, s2),
            CoseError::UnregisteredIanaValue => CborError::UnregisteredIanaValue,
            CoseError::UnregisteredIanaNonPrivateValue => {
                CborError::UnregisteredIanaNonPrivateValue
            }
        }
    }
}

pub fn to_vec<T>(value: &T) -> Result<Vec<u8>, CborError>
where
    T: serde::Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(coset::CoseError::from)
        .map_err(CborError::from)?;
    Ok(buf)
}

pub fn from_slice<T>(slice: &[u8]) -> Result<T, CborError>
where
    T: de::DeserializeOwned,
{
    ciborium::from_reader(Cursor::new(&slice))
        .map_err(|e| CoseError::DecodeFailed(ciborium::de::Error::Semantic(None, e.to_string())))
        .map_err(CborError::from)
}

/// Convert a `ciborium::Value` into a type `T`
#[allow(clippy::needless_pass_by_value)]
pub fn from_value<T>(value: ciborium::Value) -> Result<T, CborError>
where
    T: de::DeserializeOwned,
{
    // TODO implement in a way that doesn't require
    // roundtrip through buffer (i.e. by implementing
    // `serde::de::Deserializer` for `Value` and then doing
    // `T::deserialize(value)`).
    let buf = to_vec(&value)?;
    from_slice(buf.as_slice())
}

pub fn into_value<S>(v: S) -> Result<Value, CborError>
where
    S: Serialize,
{
    let bytes = to_vec(&v)?;
    from_slice(&bytes)
}
