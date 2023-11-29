use std::collections::BTreeMap;
use serde_json::Value;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct ValidatedResponse {
    pub response: BTreeMap<String, Value>,
    pub issuer_authentication: Status,
    pub device_authentication: Status,
    pub errors: ValidationErrors,
}

#[derive(Serialize, Deserialize)]
pub struct ValidationErrors(pub BTreeMap<String, serde_json::Value>);

#[derive(Serialize, Deserialize)]
pub enum Status {
    Unchecked,
    Invalid,
    Valid,
}