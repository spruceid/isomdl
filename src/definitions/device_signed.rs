use crate::cose::mac0::CoseMac0;
use crate::cose::sign1::CoseSign1;
use crate::definitions::{
    helpers::{NonEmptyMap, Tag24},
    session::SessionTranscript,
};
use serde::{Deserialize, Serialize};
use serde_cbor::{Error as CborError, Value as CborValue};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSigned {
    #[serde(rename = "nameSpaces")]
    pub namespaces: DeviceNamespacesBytes,
    pub device_auth: DeviceAuth,
}

pub type DeviceNamespacesBytes = Tag24<DeviceNamespaces>;
pub type DeviceNamespaces = BTreeMap<String, DeviceSignedItems>;
pub type DeviceSignedItems = NonEmptyMap<String, CborValue>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DeviceAuth {
    #[serde(rename_all = "camelCase")]
    Signature { device_signature: CoseSign1 },
    #[serde(rename_all = "camelCase")]
    Mac { device_mac: CoseMac0 },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceAuthType {
    #[serde(rename_all = "camelCase")]
    Sign1,
    #[serde(rename_all = "camelCase")]
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
