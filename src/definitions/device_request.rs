//! This module contains the definitions for the device request functionality.
use crate::cose::MaybeTagged;
use crate::definitions::helpers::{NonEmptyMap, NonEmptyVec, Tag24};
use coset::CoseSign1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type ItemsRequestBytes = Tag24<ItemsRequest>;
pub type ItemsRequestBytesAll = Vec<ItemsRequestBytes>;
pub type DeviceRequestInfoBytes = Tag24<DeviceRequestInfo>;
pub type DocType = String;
pub type NameSpace = String;
pub type IntentToRetain = bool;
pub type DataElementIdentifier = String;
pub type DataElements = NonEmptyMap<DataElementIdentifier, IntentToRetain>;
pub type Namespaces = NonEmptyMap<NameSpace, DataElements>;
pub type ReaderAuth = MaybeTagged<CoseSign1>;
pub type DocumentSet = NonEmptyVec<DocRequestID>;
pub type DocRequestID = u64;
pub type PurposeHints = NonEmptyMap<PurposeControllerId, PurposeCode>;
pub type PurposeControllerId = String;
pub type PurposeCode = i64;

/// Represents a device request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequest {
    /// The version of the device request.
    pub version: String,

    /// A non-empty vector of document requests.
    pub doc_requests: NonEmptyVec<DocRequest>,

    /// An optional non-empty vector of reader authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reader_auth_all: Option<NonEmptyVec<MaybeTagged<CoseSign1>>>,

    /// An optional device request information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_request_info: Option<Tag24<DeviceRequestInfo>>,
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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

/// Represents a use case.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UseCase {
    /// Whether this use case is required.
    pub mandatory: bool,

    /// Document requests that must comply with this use case.
    pub document_sets: NonEmptyVec<DocumentSet>,

    /// Option hints to help the user distinguish between use cases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose_hints: Option<PurposeHints>,
}

/// Represents additional information on the set of documents requested in the mdoc request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequestInfo {
    /// A non-empty vector of use cases.
    pub use_cases: NonEmptyVec<UseCase>,
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

    #[test]
    fn device_request_v11() {
        const HEX: &str = "a46776657273696f6e63312e316b646f63526571756573747381a16c6974656d7352657175657374d818586ea267646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6a6e616d65537061636573a1716f72672e69736f2e31383031332e352e31a468706f727472616974f56a676976656e5f6e616d65f56b6167655f6f7665725f3231f46b66616d696c795f6e616d65f56d72656164657241757468416c6c818443a10126a1182159017d30820179308201200209009dbe1a6d4dd57b70300a06082a8648ce3d0403023045311a3018060355040a0c1154657374204f7267616e697a6174696f6e3127302506035504030c1e5465737420526571756573742041757468656e7469636174696f6e204341301e170d3235303532373230343830305a170d3335303532353230343830305a3045311a3018060355040a0c1154657374204f7267616e697a6174696f6e3127302506035504030c1e5465737420526571756573742041757468656e7469636174696f6e2043413059301306072a8648ce3d020106082a8648ce3d030107034200048b7d4c6a005b6bb6e588bf0b3a6dab6d71354aa894975fbe904345505874c5d2b1dc31b1b976247de01776223fa565770608d14c45d3e0ad920502a09f8b8da3300a06082a8648ce3d0403020347003044022047c3dae3eebfc6f1e2e66ed22dc900d1099d8d585413379a9bf48792998ce00102207e47ee580a3b0d02d26148be0186f1cc92ec852e93ac0622c99cec98ed5fd7a6f65840a4285751d90bb408115e99aafd11872d7a5f6b3494610de68b99d70d8c3bdd1f72ab0fe0c8e483bf1a63c047922a41c4758b7befb5aef0eb24bf08ea0223da857164657669636552657175657374496e666fd8185827a168757365436173657381a2696d616e6461746f7279f56c646f63756d656e7453657473818100";
        let bytes: Vec<u8> = hex::decode(HEX).unwrap();
        let req: DeviceRequest = crate::cbor::from_slice(&bytes).unwrap();
        let roundtripped = crate::cbor::to_vec(&req).unwrap();
        assert_eq!(bytes, roundtripped);
    }
}
