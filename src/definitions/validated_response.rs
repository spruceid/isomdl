use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ValidatedResponse {
    pub response: BTreeMap<String, Value>,
    pub decryption: Status,
    pub parsing: Status,
    pub issuer_authentication: Status,
    pub device_authentication: Status,
    pub errors: ValidationErrors,
}

pub type ValidationErrors = BTreeMap<String, serde_json::Value>;

#[derive(Debug, Serialize, Deserialize, Default)]
pub enum Status {
    #[default]
    Unchecked,
    Invalid,
    Valid,
}
