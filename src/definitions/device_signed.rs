//! This module contains the definitions related to device signing.
//!
//! The [DeviceSigned] struct represents a device signed object, which includes namespaces and device authentication information.
//!
//! The [Error] enum represents the possible errors that can occur in this module.  
//! - [Error::UnableToEncode]: Indicates an error when encoding a value as CBOR.
use crate::cose::MaybeTagged;
use crate::definitions::{
    helpers::{NonEmptyMap, Tag24},
    session::SessionTranscript,
};
use coset::{CoseMac0, CoseSign1};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Represents a device-signed structure.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSigned {
    #[serde(rename = "nameSpaces")]
    /// A [DeviceNamespacesBytes] struct representing the namespaces.
    pub namespaces: DeviceNamespacesBytes,

    /// A [DeviceAuth] struct representing the device authentication.
    pub device_auth: DeviceAuth,
}

pub type DeviceNamespacesBytes = Tag24<DeviceNamespaces>;
pub type DeviceNamespaces = BTreeMap<String, DeviceSignedItems>;
pub type DeviceSignedItems = NonEmptyMap<String, ciborium::Value>;

/// Represents a device signature.
///
/// This struct contains the device signature in the form of a [CoseSign1] object.  
/// The [CoseSign1] object represents a `COSE (CBOR Object Signing and Encryption) signature.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceAuth {
    DeviceSignature(MaybeTagged<CoseSign1>),
    DeviceMac(MaybeTagged<CoseMac0>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DeviceAuthType {
    Sign1,
    Mac0,
}

pub type DeviceAuthenticationBytes<S> = Tag24<DeviceAuthentication<S>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceAuthentication<S: SessionTranscript>(
    &'static str,
    // See https://github.com/serde-rs/serde/issues/1296.
    #[serde(bound = "")] S,
    String,
    DeviceNamespacesBytes,
);

impl<S: SessionTranscript> DeviceAuthentication<S> {
    pub fn new(transcript: S, doc_type: String, namespaces_bytes: DeviceNamespacesBytes) -> Self {
        Self(
            "DeviceAuthentication",
            transcript,
            doc_type,
            namespaces_bytes,
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unable to encode value as CBOR: {0}")]
    UnableToEncode(coset::CoseError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use hex::FromHex;

    static COSE_SIGN1: &str = include_str!("../../test/definitions/cose/sign1/serialized.cbor");

    #[test]
    fn device_auth() {
        let bytes = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        let cose_sign1: MaybeTagged<CoseSign1> =
            cbor::from_slice(&bytes).expect("failed to parse COSE_Sign1 from bytes");
        let bytes2 = cbor::to_vec(&cose_sign1).unwrap();
        assert_eq!(bytes, bytes2);
        let device_auth = DeviceAuth::DeviceSignature(cose_sign1);
        let bytes = cbor::to_vec(&device_auth).unwrap();
        println!("bytes {}", hex::encode(&bytes));
        let roundtripped: DeviceAuth = cbor::from_slice(&bytes).unwrap();
        let roundtripped_bytes = cbor::to_vec(&roundtripped).unwrap();
        assert_eq!(bytes, roundtripped_bytes);
    }
}
