use crate::definitions::traits::{FromJson, FromJsonError};
use anyhow::anyhow;
use serde_json::Value;

#[derive(Debug, Copy, Clone)]
pub struct Present;

impl FromJson for Present {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        match u32::from_json(v)? {
            1 => Ok(Present),
            n => Err(anyhow!("unrecognized variant: {n}").into()),
        }
    }
}
