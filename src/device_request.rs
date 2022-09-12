use aws_nitro_enclaves_cose::CoseSign1;

use crate::mdoc::NonEmptyMap;

pub type ItemsRequestBytes = Vec<u8>;
pub type DocType = String;
pub type NameSpace = String;
pub type IntentToRetain = bool;
pub type DataElementIdentifier = String;
pub type DataElements = NonEmptyMap<DataElementIdentifier, IntentToRetain>;
pub type Namespaces = NonEmptyMap<NameSpace, DataElements>;
pub type ReaderAuth = CoseSign1;

pub struct DeviceRequest {
    version: String,
    doc_requests: Vec<DocRequest>,
}

pub struct DocRequest {
    item_request: ItemsRequestBytes,
    reader_auth: Option<ReaderAuth>,
}

pub struct ItemsRequest {
    doc_type: DocType,
    namespaces: Namespaces,
    request_info: Option<String>,
}
