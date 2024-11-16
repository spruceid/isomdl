use std::io::Cursor;

use ciborium::Value;
use coset::{cbor, CoseError};
use serde::{de, Serialize};
use std::error::Error;
use std::fmt;

pub fn to_vec<T>(value: &T) -> Result<Vec<u8>, CborError>
where
    T: serde::Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| CborError(CoseError::EncodeFailed))?;
    Ok(buf)
}

pub fn from_slice<T>(slice: &[u8]) -> Result<T, CborError>
where
    T: de::DeserializeOwned,
{
    ciborium::from_reader(Cursor::new(&slice)).map_err(|e| {
        CborError(CoseError::DecodeFailed(ciborium::de::Error::Semantic(
            None,
            e.to_string(),
        )))
    })
}

/// Convert a `ciborium::Value` into a type `T`
#[allow(clippy::needless_pass_by_value)]
pub fn from_value<T>(value: Value) -> Result<T, CoseError>
where
    T: de::DeserializeOwned,
{
    Value::deserialized(&value).map_err(|_| {
        CoseError::DecodeFailed(cbor::de::Error::Semantic(
            None,
            "cannot deserialize".to_string(),
        ))
    })
}

pub fn into_value<S>(v: S) -> Result<Value, CoseError>
where
    S: Serialize,
{
    Value::serialized(&v).map_err(|_| CoseError::EncodeFailed)
}

// Wrapper struct to implement Error for CoseError
#[derive(Debug)]
pub struct CborError(pub CoseError);

impl From<CoseError> for CborError {
    fn from(err: CoseError) -> CborError {
        CborError(err)
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Error for CborError {}
