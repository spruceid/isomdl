use ciborium::Value;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub struct ByteStr(Vec<u8>);

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Expected to parse a CBOR byte string, received: '{0:?}'")]
    NotAByteString(CborValue),
}

impl From<Vec<u8>> for ByteStr {
    fn from(bytes: Vec<u8>) -> ByteStr {
        ByteStr(bytes)
    }
}

impl From<ByteStr> for Vec<u8> {
    fn from(ByteStr(bytes): ByteStr) -> Vec<u8> {
        bytes
    }
}

impl AsRef<[u8]> for ByteStr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<ByteStr> for CborValue {
    fn from(ByteStr(bytes): ByteStr) -> CborValue {
        Value::Bytes(bytes).into()
    }
}

impl TryFrom<CborValue> for ByteStr {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<ByteStr> {
        let v2: Value = v.clone().into();
        if let Value::Bytes(bytes) = v2 {
            Ok(ByteStr(bytes))
        } else {
            Err(Error::NotAByteString(v))
        }
    }
}
