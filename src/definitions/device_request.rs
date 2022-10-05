use crate::definitions::helpers::{NonEmptyMap, NonEmptyVec};
use cose_rs::CoseSign1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    version: String,
    doc_requests: NonEmptyVec<DocRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocRequest {
    item_request: ItemsRequestBytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    reader_auth: Option<ReaderAuth>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemsRequest {
    doc_type: DocType,
    #[serde(rename = "nameSpaces")]
    namespaces: Namespaces,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_info: Option<BTreeMap<String, serde_cbor::Value>>,
}
