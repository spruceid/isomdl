//! This module contains the definitions related to device signing.
//!
//! The [DeviceSigned] struct represents a device signed object, which includes namespaces and device authentication information.
//!
//! The [Error] enum represents the possible errors that can occur in this module.  
//! - [Error::UnableToEncode]: Indicates an error when encoding a value as CBOR.
use crate::definitions::{
    helpers::{NonEmptyMap, Tag24},
    session::SessionTranscript,
};
use serde::{Deserialize, Serialize};
use serde_cbor::{Error as CborError, Value as CborValue};
use std::collections::BTreeMap;
use crate::cose::mac0::CoseMac0;
use crate::cose::sign1::CoseSign1;

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
pub type DeviceSignedItems = NonEmptyMap<String, CborValue>;

/// Represents a device signature.
///
/// This struct contains the device signature in the form of a [CoseSign1] object.  
/// The [CoseSign1] object represents a `COSE (CBOR Object Signing and Encryption) signature.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DeviceAuth {
    #[serde(rename_all = "camelCase")]
    Signature { device_signature: CoseSign1 },
    #[serde(rename_all = "camelCase")]
    Mac { device_mac: CoseMac0 },
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
    UnableToEncode(CborError),
}
