use crate::definitions::{
    helpers::{NonEmptyMap, Tag24},
    session::SessionTranscript,
};
use cose_rs::sign1::CoseSign1;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
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
    Mac { device_mac: CborValue },
}

pub type DeviceAuthenticationBytes = Tag24<DeviceAuthentication>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceAuthentication(
    &'static str,
    pub SessionTranscript,
    pub String,
    pub DeviceNamespacesBytes,
);

impl DeviceAuthentication {
    pub fn new(
        transcript: SessionTranscript,
        doc_type: String,
        namespaces_bytes: DeviceNamespacesBytes,
    ) -> Self {
        Self(
            "DeviceAuthentication",
            transcript,
            doc_type,
            namespaces_bytes,
        )
    }
}
