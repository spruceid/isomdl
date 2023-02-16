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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn items_request() {
        const HEX: &str = "D8185868A267646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6A6E616D65537061636573A1716F72672E69736F2E31383031332E352E31A36B66616D696C795F6E616D65F46A676976656E5F6E616D65F46F646F63756D656E745F6E756D626572F4";
        let bytes: Vec<u8> = hex::decode(HEX).unwrap();
        let req: Tag24<ItemsRequest> = serde_cbor::from_slice(&bytes).unwrap();
        let roundtripped = serde_cbor::to_vec(&req).unwrap();
        assert_eq!(bytes, roundtripped);
    }

    #[test]
    fn doc_request() {
        const HEX: &str = "A16C6974656D7352657175657374D8185868A267646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6A6E616D65537061636573A1716F72672E69736F2E31383031332E352E31A36B66616D696C795F6E616D65F46A676976656E5F6E616D65F46F646F63756D656E745F6E756D626572F4";
        let bytes: Vec<u8> = hex::decode(HEX).unwrap();
        let req: DocRequest = serde_cbor::from_slice(&bytes).unwrap();
        let roundtripped = serde_cbor::to_vec(&req).unwrap();
        assert_eq!(bytes, roundtripped);
    }

    #[test]
    fn device_request() {
        const HEX: &str = "A26776657273696F6E63312E306B646F63526571756573747381A16C6974656D7352657175657374D8185868A267646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6A6E616D65537061636573A1716F72672E69736F2E31383031332E352E31A36B66616D696C795F6E616D65F46A676976656E5F6E616D65F46F646F63756D656E745F6E756D626572F4";
        let bytes: Vec<u8> = hex::decode(HEX).unwrap();
        let req: DeviceRequest = serde_cbor::from_slice(&bytes).unwrap();
        let roundtripped = serde_cbor::to_vec(&req).unwrap();
        assert_eq!(bytes, roundtripped);
    }
}
