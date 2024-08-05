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

use crate::cose::key::CoseKey;
use crate::definitions::helpers::Tag24;
use hkdf::Hkdf;
use sha2::Sha256;

fn calculate_ble_ident(e_device_key: &Tag24<CoseKey>) -> Result<[u8; 16]> {
    let e_device_key_bytes = serde_cbor::to_vec(e_device_key)?;
    let mut ble_ident = [0u8; 16];

    Hkdf::<Sha256>::new(None, &e_device_key_bytes)
        .expand("BLEIdent".as_bytes(), &mut ble_ident)
        .map_err(|e| anyhow::anyhow!("unable to perform HKDF: {}", e))?;

    Ok(ble_ident)
}
