use std::borrow::{Borrow, BorrowMut};
use std::cmp::Ordering;
use std::io::Cursor;
use std::ops::{Deref, DerefMut};

use coset::{cbor, CoseError, EndOfFile};
use serde::{de, Deserialize, Serialize};
use thiserror::Error;

/// Wraps [ciborium::Value] and implements [PartialEq], [Eq], [PartialOrd] and [Ord],
/// so it can be used in maps and sets.
///
/// [IEEE754](https://www.rfc-editor.org/rfc/rfc8949.html#IEEE754)
/// non-finite floats do not have a total ordering,
/// which means [`Ord`] cannot be correctly implemented for types that may contain them.
/// That's why we don't support such values.
///
/// Also, useful in future if we want to change the CBOR library.
#[derive(Debug, Clone)]
pub struct Value(ciborium::Value);

impl Value {
    /// Create a new CBOR value.
    ///
    /// Return an error if the value contains non-finite floats or NaN.
    pub fn from(value: ciborium::Value) -> Result<Self, CborError> {
        // Validate the CBOR value. If it contains non-finite floats, return an error.
        if contains_non_finite_floats(&value) {
            Err(CborError::NonFiniteFloats)
        } else {
            Ok(Value(value))
        }
    }

    /// Unsafe version of `new`.
    ///
    /// # Safety
    ///
    /// It will allow creating from value containing non-finite floats or NaN.
    pub unsafe fn from_unsafe(value: ciborium::Value) -> Self {
        Value(value)
    }

    pub fn into_inner(self) -> ciborium::Value {
        self.0
    }
}

// Helper function to check for non-finite floats
fn contains_non_finite_floats(value: &ciborium::Value) -> bool {
    match value {
        ciborium::Value::Float(f) => !f.is_finite(),
        ciborium::Value::Array(arr) => arr.iter().any(contains_non_finite_floats),
        ciborium::Value::Map(map) => map
            .iter()
            .any(|(k, v)| contains_non_finite_floats(k) || contains_non_finite_floats(v)),
        _ => false,
    }
}

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

impl Value {
    pub fn to_string(&self) -> coset::Result<String> {
        self.0.clone().into_text().map_err(|e| {
            CoseError::DecodeFailed(ciborium::de::Error::Semantic(None, format!("{e:?}")))
        })
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

impl Eq for Value {}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.partial_cmp(&other.0).unwrap()
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
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

impl TryFrom<ciborium::Value> for Value {
    type Error = CborError;

    fn try_from(value: ciborium::Value) -> Result<Self, Self::Error> {
        Value::from(value)
    }
}

impl From<Value> for ciborium::Value {
    fn from(val: Value) -> Self {
        val.0
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
        ciborium::Value::deserialize(deserializer).map(Value)
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
                unsafe { Value::from_unsafe($variant(v.into())) }
            }
        }
    };
}

impl_from!(ciborium::Value::Bool, bool);
impl_from!(ciborium::Value::Bytes, Vec<u8>);
impl_from!(ciborium::Value::Bytes, &[u8]);
impl_from!(ciborium::Value::Text, String);
impl_from!(ciborium::Value::Text, &str);
impl_from!(ciborium::Value::Array, Vec<ciborium::Value>);
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

#[cfg(test)]
mod tests {
    use crate::cbor::{CborError, Value};

    #[test]
    fn conversions() {
        assert_eq!(
            Value::from(ciborium::Value::Bool(true)),
            Ok(ciborium::Value::Bool(true).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Integer(1i8.into())),
            Ok(ciborium::Value::Integer(1i8.into()).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Integer(1i16.into())),
            Ok(ciborium::Value::Integer(1i16.into()).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Integer(1i32.into())),
            Ok(ciborium::Value::Integer(1i32.into()).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Integer(1i64.into())),
            Ok(ciborium::Value::Integer(1i64.into()).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Integer(1u8.into())),
            Ok(ciborium::Value::Integer(1u8.into()).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Integer(1u16.into())),
            Ok(ciborium::Value::Integer(1u16.into()).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Integer(1u32.into())),
            Ok(ciborium::Value::Integer(1u32.into()).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Integer(1u64.into())),
            Ok(ciborium::Value::Integer(1u64.into()).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Float(1.0f32.into())),
            Ok(ciborium::Value::Float(1.0f32.into()).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Float(1.0f64)),
            Ok(ciborium::Value::Float(1.0f64).try_into().unwrap())
        );
        assert_eq!(
            Value::from(ciborium::Value::Text("foo".to_string())),
            Ok(ciborium::Value::Text("foo".to_string()).try_into().unwrap())
        );
    }

    #[test]
    fn non_finite_floats() {
        assert_eq!(
            Value::from(ciborium::Value::from(f32::NAN)),
            Err(CborError::NonFiniteFloats)
        );
        assert_eq!(
            Value::from(ciborium::Value::from(f32::INFINITY)),
            Err(CborError::NonFiniteFloats)
        );
        assert_eq!(
            Value::from(ciborium::Value::from(f32::NEG_INFINITY)),
            Err(CborError::NonFiniteFloats)
        );
        assert_eq!(
            Value::from(ciborium::Value::from(f64::NAN)),
            Err(CborError::NonFiniteFloats)
        );
        assert_eq!(
            Value::from(ciborium::Value::from(f64::NEG_INFINITY)),
            Err(CborError::NonFiniteFloats)
        );
    }

    #[test]
    #[should_panic]
    fn non_finite_floats_no_panic() {
        let _ = Value::from(ciborium::Value::from(f32::NAN)).unwrap();
    }

    #[test]
    fn non_finite_floats_unsafe() {
        unsafe {
            assert!(Value::from_unsafe(ciborium::Value::from(f32::NAN))
                .0
                .into_float()
                .unwrap()
                .is_nan());
            assert!(Value::from_unsafe(ciborium::Value::from(f32::INFINITY))
                .0
                .into_float()
                .unwrap()
                .is_infinite());
            assert!(Value::from_unsafe(ciborium::Value::from(f32::NEG_INFINITY))
                .0
                .into_float()
                .unwrap()
                .is_infinite());
            assert!(Value::from_unsafe(ciborium::Value::from(f64::NAN))
                .0
                .into_float()
                .unwrap()
                .is_nan());
            assert!(Value::from_unsafe(ciborium::Value::from(f64::INFINITY))
                .0
                .into_float()
                .unwrap()
                .is_infinite());
            assert!(Value::from_unsafe(ciborium::Value::from(f64::NEG_INFINITY))
                .0
                .into_float()
                .unwrap()
                .is_infinite());
        }
    }
}
