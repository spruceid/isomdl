use crate::definitions::helpers::{NonEmptyMap, Tag24};
use crate::presentation::device::DeviceSession;
use cose_rs::sign1::CoseSign1;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::collections::BTreeMap;

use super::session::AttendedSessionTranscript;

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

pub type DeviceAuthenticationBytes = Tag24<AttendedDeviceAuthentication>;

#[derive(Clone, Deserialize, Serialize)]
pub struct AttendedDeviceAuthentication(
    &'static str,
    pub <crate::presentation::device::SessionManager as DeviceSession>::T,
    pub String,
    pub DeviceNamespacesBytes,
);

impl AttendedDeviceAuthentication {
    pub fn new(
        transcript: AttendedSessionTranscript,
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
