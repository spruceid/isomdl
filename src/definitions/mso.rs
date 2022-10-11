use crate::definitions::{helpers::ByteStr, DeviceKeyInfo, ValidityInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type DigestId = u64;
pub type DigestIds = HashMap<DigestId, ByteStr>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mso {
    pub version: String,
    pub digest_algorithm: DigestAlgorithm,
    pub value_digests: HashMap<String, DigestIds>,
    pub device_key_info: DeviceKeyInfo,
    pub doc_type: String,
    pub validity_info: ValidityInfo,
}

#[derive(Clone, Debug, Copy, Deserialize, Serialize)]
pub enum DigestAlgorithm {
    #[serde(rename = "SHA-256")]
    SHA256,
    #[serde(rename = "SHA-384")]
    SHA384,
    #[serde(rename = "SHA-512")]
    SHA512,
}
