use std::borrow::{Borrow, BorrowMut};
use std::ops::{Deref, DerefMut};
use serde::{de, Deserialize, Serialize};
use std::io::Cursor;
use coset::{cbor, CoseError, EndOfFile};
use thiserror::Error;

/// Wraps [chromium::Value] and implements [PartialEq], [Eq], [PartialOrd] and [Ord],
/// so it can be used in maps and sets.
///
/// Also, useful in future if we want to change the CBOR library.
#[derive(Debug, Clone)]
pub struct Value(pub ciborium::Value);

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
            CoseError::UnregisteredIanaNonPrivateValue => CborError::UnregisteredIanaNonPrivateValue,
        }
    }
}

impl Value {
    pub fn to_string(&self) -> coset::Result<String> {
        self.0.clone().into_text().map_err(|e| CoseError::DecodeFailed(ciborium::de::Error::Semantic(
            None,
            format!("{e:?}"),
        )))
    }
}

impl Deref for Value {
    type Target = ciborium::Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Value {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Value {}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.partial_cmp(&other.0).unwrap()
    }
}

pub fn to_vec<T>(value: &T) -> Result<Vec<u8>, CborError>
where
    T: serde::Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(coset::CoseError::from).map_err(CborError::from)?;
    Ok(buf)
}

pub fn from_slice<T>(slice: &[u8]) -> Result<T, CborError>
where
    T: de::DeserializeOwned,
{
    ciborium::from_reader(Cursor::new(&slice)).map_err(|e| CoseError::DecodeFailed(ciborium::de::Error::Semantic(
        None,
        e.to_string(),
    ))).map_err(CborError::from)
}

/// Convert a `chor::Value` into a type `T`
#[allow(clippy::needless_pass_by_value)]
pub fn from_value2<T>(value: Value) -> Result<T, CborError>
where
    T: de::DeserializeOwned,
{
    from_value(value.0)
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

pub fn into_value<S>(v: S) -> Result<ciborium::Value, CborError>
where
    S: Serialize,
{
    let bytes = to_vec(&v)?;
    from_slice(&bytes)
}

impl From<ciborium::Value> for Value {
    fn from(value: ciborium::Value) -> Self {
        Self(value)
    }
}

impl Into<ciborium::Value> for Value {
    fn into(self) -> ciborium::Value {
        self.0
    }
}

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> crate::cose::sign1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> crate::cose::sign1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ciborium::Value::deserialize(deserializer).map(|v| Value(v))
    }
}

impl AsRef<ciborium::Value> for Value {
    fn as_ref(&self) -> &ciborium::Value {
        &self.0
    }
}

impl Borrow<ciborium::Value> for Value {
    fn borrow(&self) -> &ciborium::Value {
        &self.0
    }
}

impl BorrowMut<ciborium::Value> for Value {
    fn borrow_mut(&mut self) -> &mut ciborium::Value {
        &mut self.0
    }
}

macro_rules! impl_from {
    ($variant:path, $for_type:ty) => {
        impl From<$for_type> for Value {
            fn from(v: $for_type) -> Value {
                $variant(v.into()).into()
            }
        }
    };
}

impl_from!(ciborium::Value::Bool, bool);
impl_from!(ciborium::Value::Integer, i8);
impl_from!(ciborium::Value::Integer, i16);
impl_from!(ciborium::Value::Integer, i32);
impl_from!(ciborium::Value::Integer, i64);
// i128 omitted because not all numbers fit in CBOR serialization
impl_from!(ciborium::Value::Integer, u8);
impl_from!(ciborium::Value::Integer, u16);
impl_from!(ciborium::Value::Integer, u32);
impl_from!(ciborium::Value::Integer, u64);
// u128 omitted because not all numbers fit in CBOR serialization
impl_from!(ciborium::Value::Float, f32);
impl_from!(ciborium::Value::Float, f64);
impl_from!(ciborium::Value::Bytes, Vec<u8>);
impl_from!(ciborium::Value::Text, String);
impl_from!(ciborium::Value::Array, Vec<ciborium::Value>);
