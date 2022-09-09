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
#[serde(untagged)]
pub enum DeviceAuth {
    #[serde(rename_all = "camelCase")]
    Signature { device_signature: CoseSign1 },
    /// TODO: Implement CoseMac0
    #[serde(rename_all = "camelCase")]
    Mac { device_mac: CborValue },
}

pub type Errors = NonEmptyMap<String, NonEmptyMap<String, i128>>;

pub type DocumentErrors = NonEmptyVec<HashMap<String, i128>>;

#[cfg(test)]
mod test {
    use super::DeviceResponse;
    use hex::FromHex;

    static DEVICE_RESPONSE_CBOR: &str = include_str!("../test/device_response.cbor");

    #[test]
    fn serde_device_response() {
        let cbor_bytes = <Vec<u8>>::from_hex(DEVICE_RESPONSE_CBOR).expect("unable to convert cbor hex to bytes");
        let response: DeviceResponse = serde_cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as a DeviceResponse");
        let roundtripped_bytes = serde_cbor::to_vec(&response).expect("unable to encode DeviceResponse as cbor bytes");
        assert_eq!(cbor_bytes, roundtripped_bytes, "original cbor and re-serialized DeviceResponse do not match");
    }
}
