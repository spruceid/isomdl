use crate::mdoc::NonEmptyMap;
use aws_nitro_enclaves_cose::CoseSign1;
use serde::{Deserialize, Serialize};

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
    doc_requests: Vec<DocRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocRequest {
    item_request: ItemsRequestBytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reader_auth: Option<ReaderAuth>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemsRequest {
    doc_type: DocType,
    #[serde(rename = "nameSpaces")]
    namespaces: Namespaces,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_info: Option<String>,
}
