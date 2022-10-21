use crate::definitions::helpers::{NonEmptyMap, NonEmptyVec, Tag24};
use cose_rs::CoseSign1;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type ItemsRequestBytes = Tag24<ItemsRequest>;
pub type DocType = String;
pub type NameSpace = String;
pub type IntentToRetain = bool;
pub type DataElementIdentifier = String;
pub type DataElements = NonEmptyMap<DataElementIdentifier, IntentToRetain>;
pub type Namespaces = NonEmptyMap<NameSpace, DataElements>;
pub type ReaderAuth = CoseSign1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequest {
    pub version: String,
    pub doc_requests: NonEmptyVec<DocRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocRequest {
    pub items_request: ItemsRequestBytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reader_auth: Option<ReaderAuth>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemsRequest {
    pub doc_type: DocType,
    #[serde(rename = "nameSpaces")]
    pub namespaces: Namespaces,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_info: Option<HashMap<String, serde_cbor::Value>>,
}

impl DeviceRequest {
    pub const VERSION: &'static str = "1.0";
}
