use crate::mdoc::{IssuerSigned, NonEmptyMap, NonEmptyVec, Tag24};
use aws_nitro_enclaves_cose::CoseSign1;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    documents: Option<Documents>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    document_errors: Option<DocumentErrors>,
    status: u64,
}

pub type Documents = NonEmptyVec<Document>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    doc_type: String,
    issuer_signed: IssuerSigned,
    device_signed: DeviceSigned,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    errors: Option<Errors>,
}

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
#[serde(untagged, rename_all = "camelCase")]
pub enum DeviceAuth {
    Signature { device_signature: CoseSign1 },
    // TBD: Mac { device_mac: CoseMac0 },
}

pub type Errors = NonEmptyMap<String, NonEmptyMap<String, i128>>;

pub type DocumentErrors = NonEmptyVec<HashMap<String, i128>>;
