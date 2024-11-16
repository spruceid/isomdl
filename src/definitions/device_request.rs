//! This module contains the definitions for the device request functionality.
use crate::cose::MaybeTagged;
use crate::definitions::helpers::{NonEmptyMap, NonEmptyVec, Tag24};
use coset::CoseSign1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type ItemsRequestBytes = Tag24<ItemsRequest>;
pub type DocType = String;
pub type NameSpace = String;
pub type IntentToRetain = bool;
pub type DataElementIdentifier = String;
pub type DataElements = NonEmptyMap<DataElementIdentifier, IntentToRetain>;
pub type Namespaces = NonEmptyMap<NameSpace, DataElements>;
pub type ReaderAuth = MaybeTagged<CoseSign1>;

/// Represents a device request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]

pub struct DeviceRequest {
    /// The version of the device request.
    pub version: String,

    /// A non-empty vector of document requests.
    pub doc_requests: NonEmptyVec<DocRequest>,
}

/// Represents a document request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocRequest {
    /// The items request for the document.
    pub items_request: ItemsRequestBytes,

    /// The reader authentication, if provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reader_auth: Option<ReaderAuth>,
}

/// Represents a request for items.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemsRequest {
    /// The type of document.
    pub doc_type: DocType,

    /// The namespaces associated with the request.
    #[serde(rename = "nameSpaces")]
    pub namespaces: Namespaces,

    /// Additional information for the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_info: Option<BTreeMap<String, ciborium::Value>>,
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
        let req: Tag24<ItemsRequest> = crate::cbor::from_slice(&bytes).unwrap();
        let roundtripped = crate::cbor::to_vec(&req).unwrap();
        assert_eq!(bytes, roundtripped);
    }

    #[test]
    fn doc_request() {
        const HEX: &str = "A16C6974656D7352657175657374D8185868A267646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6A6E616D65537061636573A1716F72672E69736F2E31383031332E352E31A36B66616D696C795F6E616D65F46A676976656E5F6E616D65F46F646F63756D656E745F6E756D626572F4";
        let bytes: Vec<u8> = hex::decode(HEX).unwrap();
        let req: DocRequest = crate::cbor::from_slice(&bytes).unwrap();
        let roundtripped = crate::cbor::to_vec(&req).unwrap();
        assert_eq!(bytes, roundtripped);
    }

    #[test]
    fn device_request() {
        const HEX: &str = "A26776657273696F6E63312E306B646F63526571756573747381A16C6974656D7352657175657374D8185868A267646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6A6E616D65537061636573A1716F72672E69736F2E31383031332E352E31A36B66616D696C795F6E616D65F46A676976656E5F6E616D65F46F646F63756D656E745F6E756D626572F4";
        let bytes: Vec<u8> = hex::decode(HEX).unwrap();
        let req: DeviceRequest = crate::cbor::from_slice(&bytes).unwrap();
        let roundtripped = crate::cbor::to_vec(&req).unwrap();
        assert_eq!(bytes, roundtripped);
    }
}
