//! This module responsible on handling the interaction between the device and reader.
//!
//! You can see examples on how to use this module in `examples`
//! directory and read about in the dedicated `README.md`.
//!
//! # **Device** and **Reader** interaction
//!
//! This flow demonstrates a simulated device and reader interaction.
//! The reader requests the `age_over_21` element, and the device responds with that value.
//! The flow is something like this:
//!
//! ```ignore
#![doc = include_str!("../../docs/simulated_device_and_reader.txt")]
//! ```
//!
//! ## The flow of the interaction
//!
//! 1. **Device initialization and engagement:**
//!     - The device creates a `QR code` containing `DeviceEngagement` data, which includes its public key.
//!     - Internally:
//!         - The device initializes with the `mDL` data, private key, and public key.
//! 2. **Reader processing `QR code` and requesting needed fields:**
//!     - The reader processes the QR code and creates a request for the `age_over_21` element.
//!     - Internally:
//!         - Generates its private and public keys.
//!         - Initiates a key exchange, and generates the session keys.
//!         - The request is encrypted with the reader's session key.
//! 3. **Device accepting request and responding:**
//!     - The device receives the request and creates a response with the `age_over_21` element.
//!     - Internally:
//!         - Initiates the key exchange, and generates the session keys.
//!         - Decrypts the request with the reader's session key.
//!         - Parse and validate it creating error response if needed.
//!         - The response is encrypted with the device's session key.
//! 4. **Reader Processing mDL data:**
//!     - The reader processes the response and prints the value of the `age_over_21` element.
//!
//! ### Examples
//!
//! You can see the example in `simulated_device_and_reader.rs` from `examples` directory or a version that
//! uses **State pattern**, `Arc` and `Mutex` `simulated_device_and_reader_state.rs`.
pub mod authentication;
pub mod device;
pub mod reader;
pub mod reader_utils;

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
    /// use isomdl::cbor::from_slice;
    /// use isomdl::presentation::{device, Stringify};
    /// use isomdl::presentation::device::Document;
    ///
    /// let doc_str = include_str!("../../test/stringified-mdl.txt").to_string();
    /// let doc : Document = from_slice(&decode(doc_str).unwrap()).unwrap();
    /// let serialized = doc.stringify().unwrap();
    /// assert_eq!(serialized, Document::parse(serialized.clone()).unwrap().stringify().unwrap());
    /// ```
    fn stringify(&self) -> Result<String> {
        let data = crate::cbor::to_vec(self)?;
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
    /// use isomdl::cbor::from_slice;
    /// use isomdl::presentation::{device, Stringify};
    /// use isomdl::presentation::device::Document;
    ///
    /// let doc_str = include_str!("../../test/stringified-mdl.txt").to_string();
    /// let doc : Document = from_slice(&decode(doc_str).unwrap()).unwrap();
    /// let serialized = doc.stringify().unwrap();
    /// assert_eq!(serialized, Document::parse(serialized.clone()).unwrap().stringify().unwrap());
    /// ```
    fn parse(encoded: String) -> Result<Self> {
        let data = decode(encoded)?;
        let this = crate::cbor::from_slice(&data)?;
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
    let e_device_key_bytes = crate::cbor::to_vec(e_device_key)?;
    let mut ble_ident = [0u8; 16];

    Hkdf::<Sha256>::new(None, &e_device_key_bytes)
        .expand("BLEIdent".as_bytes(), &mut ble_ident)
        .map_err(|e| anyhow::anyhow!("unable to perform HKDF: {}", e))?;

    Ok(ble_ident)
}
