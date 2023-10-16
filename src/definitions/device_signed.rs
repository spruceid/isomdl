use crate::definitions::{
    helpers::{NonEmptyMap, Tag24},
    session::SessionTranscript,
};
use cose_rs::sign1::CoseSign1;
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
    Mac { device_mac: CborValue },
}

pub type DeviceAuthenticationBytes = Tag24<DeviceAuthentication>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceAuthentication(&'static str, CborValue, String, DeviceNamespacesBytes);

impl DeviceAuthentication {
    pub fn new<S: SessionTranscript>(
        transcript: S,
        doc_type: String,
        namespaces_bytes: DeviceNamespacesBytes,
    ) -> Result<Self, Error> {
        Ok(Self(
            "DeviceAuthentication",
            serde_cbor::value::to_value(transcript).map_err(Error::UnableToEncode)?,
            doc_type,
            namespaces_bytes,
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unable to encode value as CBOR: {0}")]
    UnableToEncode(CborError),
}
