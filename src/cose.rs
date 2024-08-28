use ciborium::value::Integer;
use ciborium::Value;
use coset::iana;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_cbor::Value as SerdeCborValue;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};

pub mod mac0;
mod serialize;
pub mod sign1;

/// Tag constants
pub mod tag {
    #![allow(missing_docs)]

    pub const BIGPOS: u64 = 2;
    pub const BIGNEG: u64 = 3;
}

enum Error {
    Deserialize(&'static str),
}

/// Trait to represent the signature algorithm of a signer or verifier.
pub trait SignatureAlgorithm {
    fn algorithm(&self) -> iana::Algorithm;
}

pub fn serde_cbor_value_into_ciborium_value(
    val: &SerdeCborValue,
) -> coset::Result<ciborium::Value> {
    match val {
        SerdeCborValue::Null => Ok(ciborium::Value::Null),
        SerdeCborValue::Bool(b) => Ok(ciborium::Value::Bool(*b)),
        SerdeCborValue::Integer(i) => Ok(ciborium::Value::Integer((*i).try_into()?)),
        SerdeCborValue::Float(f) => Ok(ciborium::Value::Float(*f)),
        SerdeCborValue::Bytes(b) => Ok(ciborium::Value::Bytes(b.clone())),
        SerdeCborValue::Text(t) => Ok(ciborium::Value::Text(t.to_string())),
        SerdeCborValue::Array(a) => Ok(ciborium::Value::Array(
            a.into_iter()
                .flat_map(serde_cbor_value_into_ciborium_value)
                .collect(),
        )),
        SerdeCborValue::Map(m) => Ok(ciborium::Value::Map(
            m.into_iter()
                .flat_map(|(k, v)| {
                    Ok::<(ciborium::Value, ciborium::Value), coset::CoseError>((
                        serde_cbor_value_into_ciborium_value(k)?,
                        serde_cbor_value_into_ciborium_value(v)?,
                    ))
                })
                .collect(),
        )),
        SerdeCborValue::Tag(t, v) => Ok(ciborium::Value::Tag(
            *t,
            Box::new(serde_cbor_value_into_ciborium_value(&*v)?),
        )),
        _ => unimplemented!("Unsupported cbor value {val:?}"),
    }
}

pub fn ciborium_value_into_serde_cbor_value(
    val: &ciborium::Value,
) -> coset::Result<SerdeCborValue> {
    match val {
        Value::Null => Ok(SerdeCborValue::Null),
        Value::Bool(b) => Ok(SerdeCborValue::Bool(*b)),
        Value::Integer(i) => Ok(SerdeCborValue::Integer((*i).into())),
        Value::Float(f) => Ok(SerdeCborValue::Float(*f)),
        Value::Bytes(b) => Ok(SerdeCborValue::Bytes(b.clone())),
        Value::Text(t) => Ok(SerdeCborValue::Text(t.to_string())),
        Value::Array(a) => Ok(SerdeCborValue::Array(
            a.into_iter()
                .flat_map(ciborium_value_into_serde_cbor_value)
                .collect(),
        )),
        Value::Map(m) => Ok(SerdeCborValue::Map(
            m.into_iter()
                .flat_map(|(k, v)| {
                    Ok::<(SerdeCborValue, SerdeCborValue), coset::CoseError>((
                        ciborium_value_into_serde_cbor_value(k)?,
                        ciborium_value_into_serde_cbor_value(v)?,
                    ))
                })
                .collect(),
        )),
        Value::Tag(t, v) => Ok(SerdeCborValue::Tag(
            *t,
            Box::new(ciborium_value_into_serde_cbor_value(&*v)?),
        )),
        _ => unimplemented!("Unsupported cbor value {val:?}"),
    }
}

/// Wrapper for [chromium::Value] that implements [PartialEq], [Eq], [PartialOrd] and [Ord]
/// so we can use it in maps.
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct CborValue(pub Value);

impl CborValue {
    pub fn from(value: Value) -> Self {
        Self(value)
    }
}

impl Ord for CborValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (&self.0, &other.0) {
            (Value::Integer(a), Value::Integer(b)) => a.cmp(b),
            (Value::Bytes(a), Value::Bytes(b)) => a.cmp(b),
            (Value::Text(a), Value::Text(b)) => a.cmp(b),
            (Value::Array(a), Value::Array(b)) => {
                a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
            }
            (Value::Map(a), Value::Map(b)) => a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal),
            (Value::Tag(a, _), Value::Tag(b, _)) => a.cmp(b),
            _ => unimplemented!(),
        }
    }
}

impl Eq for CborValue {}

impl Hash for CborValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            Value::Integer(i) => i.hash(state),
            Value::Bytes(b) => b.hash(state),
            Value::Text(t) => t.hash(state),
            Value::Array(a) => {
                for v in a {
                    hash(v, state);
                }
            }
            Value::Map(m) => {
                for (k, v) in m {
                    hash(k, state);
                    hash(v, state);
                }
            }
            Value::Tag(t, _) => t.hash(state),
            _ => unimplemented!(),
        }
    }
}

fn hash<H: Hasher>(value: &Value, state: &mut H) {
    match value {
        Value::Integer(i) => i.hash(state),
        Value::Bytes(b) => b.hash(state),
        Value::Text(t) => t.hash(state),
        Value::Array(a) => {
            for v in a {
                hash(v, state);
            }
        }
        Value::Map(m) => {
            for (k, v) in m {
                hash(k, state);
                hash(v, state);
            }
        }
        Value::Tag(t, _) => t.hash(state),
        _ => unimplemented!(),
    }
}

impl Deref for CborValue {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CborValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for CborValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium_value_into_serde_cbor_value(&self)
            .unwrap()
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CborValue {
    fn deserialize<D>(d: D) -> Result<CborValue, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(SerdeCborValue::deserialize(d)
            .map(|v| serde_cbor_value_into_ciborium_value(&v).unwrap())
            .map(CborValue)?)
    }
}

impl AsRef<Value> for CborValue {
    fn as_ref(&self) -> &Value {
        &self.0
    }
}

impl From<CborValue> for Value {
    fn from(CborValue(v): CborValue) -> Value {
        v
    }
}

impl From<Value> for CborValue {
    fn from(v: Value) -> CborValue {
        CborValue(v)
    }
}

macro_rules! implfrom {
    ($($v:ident($t:ty)),+ $(,)?) => {
        $(
            impl From<$t> for CborValue {
                #[inline]
                fn from(value: $t) -> Self {
                    CborValue::from(Value::$v(value.into()))
                }
            }
        )+
    };
}

implfrom! {
    Integer(Integer),
    Integer(u64),
    Integer(i64),
    Integer(u32),
    Integer(i32),
    Integer(u16),
    Integer(i16),
    Integer(u8),
    Integer(i8),

    Bytes(Vec<u8>),
    Bytes(&[u8]),

    Float(f64),
    Float(f32),

    Text(String),
    Text(&str),

    Bool(bool),

    Array(&[Value]),
    Array(Vec<Value>),

    Map(&[(Value, Value)]),
    Map(Vec<(Value, Value)>),
}

impl From<u128> for CborValue {
    #[inline]
    fn from(value: u128) -> Self {
        if let Ok(x) = Integer::try_from(value) {
            return CborValue::from(Value::Integer(x));
        }

        let mut bytes = &value.to_be_bytes()[..];
        while let Some(0) = bytes.first() {
            bytes = &bytes[1..];
        }

        CborValue::from(Value::Tag(tag::BIGPOS, Value::Bytes(bytes.into()).into()))
    }
}

impl From<i128> for CborValue {
    #[inline]
    fn from(value: i128) -> Self {
        if let Ok(x) = Integer::try_from(value) {
            return CborValue::from(Value::Integer(x));
        }

        let (tag, raw) = match value.is_negative() {
            true => (tag::BIGNEG, value as u128 ^ !0),
            false => (tag::BIGPOS, value as u128),
        };

        let mut bytes = &raw.to_be_bytes()[..];
        while let Some(0) = bytes.first() {
            bytes = &bytes[1..];
        }

        CborValue::from(Value::Tag(tag, Value::Bytes(bytes.into()).into()))
    }
}

impl From<char> for CborValue {
    #[inline]
    fn from(value: char) -> Self {
        let mut v = String::with_capacity(1);
        v.push(value);
        CborValue::from(Value::Text(v))
    }
}

impl From<&String> for CborValue {
    #[inline]
    fn from(value: &String) -> Self {
        CborValue::from(Value::Text(value.to_string()))
    }
}

impl From<&Vec<u8>> for CborValue {
    #[inline]
    fn from(value: &Vec<u8>) -> Self {
        CborValue::from(Value::Bytes(value.to_vec()))
    }
}

impl From<&Value> for CborValue {
    #[inline]
    fn from(value: &Value) -> Self {
        CborValue::from(value.clone())
    }
}

impl From<&CborValue> for Value {
    #[inline]
    fn from(value: &CborValue) -> Self {
        value.0.clone()
    }
}

impl From<&CborValue> for CborValue {
    #[inline]
    fn from(value: &CborValue) -> Self {
        value.clone()
    }
}

impl TryFrom<CborValue> for u8 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u8"))
    }
}

impl TryFrom<CborValue> for i8 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i8"))
    }
}

impl TryFrom<CborValue> for u16 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u16"))
    }
}

impl TryFrom<CborValue> for i16 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i16"))
    }
}

impl TryFrom<CborValue> for u32 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u32"))
    }
}

impl TryFrom<CborValue> for i32 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i32"))
    }
}

impl TryFrom<CborValue> for u64 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u64"))
    }
}

impl TryFrom<CborValue> for i64 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i64"))
    }
}

impl TryFrom<CborValue> for u128 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u128"))
    }
}

impl TryFrom<CborValue> for i128 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i128"))
    }
}

impl TryFrom<CborValue> for bool {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_bool()
            .map_err(|_| Error::Deserialize("not a bool"))
    }
}

impl TryFrom<CborValue> for String {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_text()
            .map_err(|_| Error::Deserialize("not a bool"))
    }
}

impl TryFrom<CborValue> for Vec<u8> {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .0
            .into_bytes()
            .map_err(|_| Error::Deserialize("not bytes"))
    }
}
