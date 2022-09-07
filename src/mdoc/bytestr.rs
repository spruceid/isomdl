use serde::{Deserialize, Serialize};
use serde_cbor::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "Value", into = "Value")]
pub struct ByteStr(Vec<u8>);

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Expected to parse a CBOR byte string, received: '{0:?}'")]
    NotAByteString(Value),
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

impl From<ByteStr> for Value {
    fn from(ByteStr(bytes): ByteStr) -> Value {
        Value::Bytes(bytes)
    }
}

impl TryFrom<Value> for ByteStr {
    type Error = Error;

    fn try_from(v: Value) -> Result<ByteStr> {
        if let Value::Bytes(bytes) = v {
            Ok(ByteStr(bytes))
        } else {
            Err(Error::NotAByteString(v))
        }
    }
}
