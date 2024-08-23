//! Support for embedded
//! [CBOR Data Items](https://www.ietf.org/rfc/rfc8949.html#name-encoded-cbor-data-item),
//! also known as a tagged data item with tag number 24.

use ciborium::Value;
use coset::{AsCborValue, CborSerializable, CoseError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wrapper for a struct that is to be encoded as a CBOR tagged item, with tag number 24.
///
/// If this struct is created through deserializing CBOR, then the original byte representation is
/// preserved for future serializing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag24<T> {
    inner: T,
    pub inner_bytes: Vec<u8>,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Expected a CBOR byte string, received: '{0:?}'")]
    InvalidTag24(Box<Value>),
    #[error("Expected a CBOR tagged data item with tag number 24, received: '{0:?}'")]
    NotATag24(Value),
    #[error("Unable to encode value as CBOR: {0}")]
    UnableToEncode(CoseError),
    #[error("Unable to decode bytes to inner type: {0}")]
    UnableToDecode(CoseError),
}

impl<T> Tag24<T> {
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: CborSerializable> Tag24<T> {
    pub fn new(inner: T) -> Result<Tag24<T>> {
        let inner_bytes = inner.to_vec().map_err(Error::UnableToEncode)?;
        let inner = T::from_slice(&inner_bytes).map_err(Error::UnableToDecode)?;
        Ok(Self { inner, inner_bytes })
    }
}

impl<T: CborSerializable> Tag24<T> {
    pub fn from_bytes(inner_bytes: Vec<u8>) -> coset::Result<Tag24<T>> {
        let inner = T::from_slice(&inner_bytes)?;
        Ok(Self { inner, inner_bytes })
    }
}

impl<T: CborSerializable> TryFrom<Value> for Tag24<T> {
    type Error = Error;

    fn try_from(v: Value) -> Result<Tag24<T>> {
        match v {
            Value::Tag(24, inner_value) => match inner_value.as_ref() {
                Value::Bytes(inner_bytes) => {
                    let inner = T::from_slice(inner_bytes).map_err(Error::UnableToDecode)?;
                    Ok(Tag24 {
                        inner,
                        inner_bytes: inner_bytes.to_vec(),
                    })
                }
                _ => Err(Error::InvalidTag24(inner_value)),
            },
            _ => Err(Error::NotATag24(v)),
        }
    }
}

impl<T> From<Tag24<T>> for Value {
    fn from(Tag24 { inner_bytes, .. }: Tag24<T>) -> Value {
        Value::Tag(24, Box::new(Value::Bytes(inner_bytes)))
    }
}

impl<T> AsRef<T> for Tag24<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: CborSerializable> CborSerializable for Tag24<T> {}
impl<T: CborSerializable> AsCborValue for Tag24<T> {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        if let Value::Tag(24, inner_value) = value {
            if let Value::Bytes(inner_bytes) = *inner_value {
                let inner: T = CborSerializable::from_slice(&inner_bytes)?;
                Ok(Tag24 {
                    inner,
                    inner_bytes: inner_bytes.to_vec(),
                })
            } else {
                Err(CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "invalid inner bytes".to_string(),
                )))
            }
        } else {
            Err(CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "not tag 24".to_string(),
            )))
        }
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Tag(24, Box::new(Value::Bytes(self.inner_bytes))))
    }
}

impl<T> Serialize for Tag24<T> {
    fn serialize<S: Serializer>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error> {
        unimplemented!()
    }
}

impl<'de, T> Deserialize<'de> for Tag24<T> {
    fn deserialize<D>(_d: D) -> std::result::Result<Tag24<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::Tag24;
    use crate::definitions::helpers::string_cbor::CborString;
    use coset::CborSerializable;

    #[test]
    // A Tag24 cannot be serialized directly into a non-cbor format as it will lose the tag.
    fn non_cbor_roundtrip() {
        let original = Tag24::new(CborString::from("some data")).unwrap();
        let cbor = original.clone().to_vec().unwrap();
        let roundtripped = Tag24::<CborString>::from_slice(&cbor).unwrap();
        assert_eq!(original, roundtripped)
    }
}
