//! Support for embedded
//! [CBOR Data Items](https://www.ietf.org/rfc/rfc8949.html#name-encoded-cbor-data-item),
//! also known as a tagged data item with tag number 24.
use serde::{
    de::{self, Error as DeError},
    ser, Deserialize, Serialize,
};
use serde_cbor::{from_slice, to_vec, Error as CborError, Value as CborValue};

/// A wrapper for a struct that is to be encoded as a CBOR tagged item, with tag number 24.
///
/// If this struct is created through deserializing CBOR, then the original byte representation is
/// preserved for future serialising.
#[derive(Debug, Clone, PartialEq)]
pub struct Tag24<T> {
    inner: T,
    pub inner_bytes: Vec<u8>,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Expected a CBOR byte string, received: '{0:?}'")]
    InvalidTag24(Box<CborValue>),
    #[error("Expected a CBOR tagged data item with tag number 24, received: '{0:?}'")]
    NotATag24(CborValue),
    #[error("Unable to encode value as CBOR: {0}")]
    UnableToEncode(CborError),
    #[error("Unable to decode bytes to inner type: {0}")]
    UnableToDecode(CborError),
}

impl<T> Tag24<T> {
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Serialize> Tag24<T> {
    pub fn new(inner: T) -> Result<Tag24<T>> {
        let inner_bytes = to_vec(&inner).map_err(Error::UnableToEncode)?;
        Ok(Self { inner, inner_bytes })
    }
}

impl<T: de::DeserializeOwned> TryFrom<CborValue> for Tag24<T> {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<Tag24<T>> {
        match v {
            CborValue::Tag(24, inner_value) => match inner_value.as_ref() {
                CborValue::Bytes(inner_bytes) => {
                    let inner: T = from_slice(inner_bytes).map_err(Error::UnableToDecode)?;
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

impl<T> From<Tag24<T>> for CborValue {
    fn from(Tag24 { inner_bytes, .. }: Tag24<T>) -> CborValue {
        CborValue::Tag(24, Box::new(CborValue::Bytes(inner_bytes)))
    }
}

impl<T> AsRef<T> for Tag24<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> Serialize for Tag24<T> {
    fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        CborValue::Tag(24, Box::new(CborValue::Bytes(self.inner_bytes.clone()))).serialize(s)
    }
}

impl<'de, T: de::DeserializeOwned> Deserialize<'de> for Tag24<T> {
    fn deserialize<D>(d: D) -> Result<Tag24<T>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        CborValue::deserialize(d)?
            .try_into()
            .map_err(D::Error::custom)
    }
}
