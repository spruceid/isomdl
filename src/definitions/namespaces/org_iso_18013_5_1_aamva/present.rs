use crate::cbor::Value as Cbor;
use crate::definitions::traits::{FromJson, FromJsonError, ToCbor};
use anyhow::anyhow;
use serde_json::Value as Json;

/// Indicator of presence for elements in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
#[derive(Debug, Copy, Clone)]
pub struct Present;

impl FromJson for Present {
    fn from_json(v: &Json) -> Result<Self, FromJsonError> {
        match u32::from_json(v)? {
            1 => Ok(Present),
            n => Err(anyhow!("unrecognized variant: {n}").into()),
        }
    }
}

impl ToCbor for Present {
    fn to_cbor(self) -> Cbor {
        ciborium::Value::Integer(1.into()).try_into().unwrap()
    }
}
