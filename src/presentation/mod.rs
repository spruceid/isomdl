pub mod device;
pub mod reader;

use anyhow::Result;
use base64::{decode, encode};
use serde::{Deserialize, Serialize};

/// Trait that handles serialization of [CBOR](https://cbor.io) objects to/from [String].
/// It is an auto trait.
pub trait Stringify: Serialize + for<'a> Deserialize<'a> {
    /// Serialize to [CBOR](https://cbor.io) representation.
    ///
    /// Operation may fail, so it returns a [Result].
    ///
    /// # Example
    ///
    /// ```
    /// use base64::decode;
    /// use serde::Serialize;
    /// use isomdl::presentation::{device, Stringify};
    /// use isomdl::presentation::device::Document;
    ///
    /// let doc_str = include_str!("../../test/stringified-mdl.txt").to_string();
    /// let doc : Document = serde_cbor::from_slice(&decode(doc_str).unwrap()).unwrap();
    /// let serialized = doc.stringify().unwrap();
    /// assert_eq!(serialized, Document::parse(serialized.clone()).unwrap().stringify().unwrap());
    /// ```
    fn stringify(&self) -> Result<String> {
        let data = serde_cbor::to_vec(self)?;
        let encoded = encode(data);
        Ok(encoded)
    }

    /// Deserialize the object from the [CBOR](https://cbor.io) representation.
    ///
    /// You can call this on something returned by [Stringify::stringify].  
    /// Operation may fail, so it returns a [Result].
    ///
    /// # Example
    ///
    /// ```
    /// use base64::decode;
    /// use serde::Serialize;
    /// use isomdl::presentation::{device, Stringify};
    /// use isomdl::presentation::device::Document;
    ///
    /// let doc_str = include_str!("../../test/stringified-mdl.txt").to_string();
    /// let doc : Document = serde_cbor::from_slice(&decode(doc_str).unwrap()).unwrap();
    /// let serialized = doc.stringify().unwrap();
    /// assert_eq!(serialized, Document::parse(serialized.clone()).unwrap().stringify().unwrap());
    /// ```
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

use crate::definitions::{device_key::cose_key::CoseKey, helpers::Tag24};
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
