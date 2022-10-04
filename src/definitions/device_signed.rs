use crate::definitions::helpers::{NonEmptyMap, Tag24};
use cose_rs::sign1::CoseSign1;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSigned {
    #[serde(rename = "nameSpaces")]
    namespaces: Tag24<DeviceNamespaces>,
    device_auth: DeviceAuth,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceNamespaces {
    #[serde(flatten)]
    namespaces: HashMap<String, DeviceSignedItems>,
}

pub type DeviceSignedItems = NonEmptyMap<String, CborValue>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DeviceAuth {
    #[serde(rename_all = "camelCase")]
    Signature { device_signature: CoseSign1 },
    /// TODO: Implement CoseMac0
    #[serde(rename_all = "camelCase")]
    Mac { device_mac: CborValue },
}
