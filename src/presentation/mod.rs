pub mod device;
pub mod reader;

use anyhow::Result;
use base64::{decode, encode};
use serde::{Deserialize, Serialize};

pub trait Stringify: Serialize + for<'a> Deserialize<'a> {
    fn stringify(&self) -> Result<String> {
        let data = serde_cbor::to_vec(self)?;
        let encoded = encode(data);
        Ok(encoded)
    }

    fn parse(encoded: String) -> Result<Self> {
        let data = decode(encoded)?;
        let this = serde_cbor::from_slice(&data)?;
        Ok(this)
    }
}

impl Stringify for device::Document {}
impl Stringify for device::SessionManagerInit {}
impl Stringify for device::SessionManagerEngaged {}
impl Stringify for device::SessionManager {}
impl Stringify for reader::SessionManager {}
