use std::io;
use std::ops::Deref;

use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Default)]
pub struct CborString(String);

impl Deref for CborString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for CborString {
    fn from(s: String) -> CborString {
        CborString(s)
    }
}

impl From<&String> for CborString {
    fn from(s: &String) -> CborString {
        CborString(s.clone())
    }
}

impl From<&str> for CborString {
    fn from(s: &str) -> CborString {
        CborString(s.to_string())
    }
}

impl From<CborString> for String {
    fn from(CborString(s): CborString) -> String {
        s
    }
}

impl AsRef<str> for CborString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<CborString> for Value {
    fn from(CborString(s): CborString) -> Value {
        Value::Text(s)
    }
}

impl TryFrom<Value> for CborString {
    type Error = io::Error;

    fn try_from(v: Value) -> io::Result<CborString> {
        if let Value::Text(s) = v {
            Ok(CborString(s))
        } else {
            Err(io::Error::other("not a string"))
        }
    }
}

impl CborSerializable for CborString {}
impl AsCborValue for CborString {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        value.try_into().map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "not a string".to_string(),
            ))
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(self.0.into())
    }
}

impl Serialize for CborString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the inner String directly as a string
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CborString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize a string and wrap it in CborString
        let s = String::deserialize(deserializer)?;
        Ok(CborString(s))
    }
}
