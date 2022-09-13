use crate::definitions::helpers::{NonEmptyMap, NonEmptyVec};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::collections::HashMap;

mod cose_key;
pub use cose_key::CoseKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    pub device_key: CoseKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_authorizations: Option<KeyAuthorizations>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_info: Option<HashMap<i128, CborValue>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorizations {
    #[serde(skip_serializing_if = "Option::is_none", rename = "nameSpaces")]
    pub namespaces: Option<NonEmptyVec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_elements: Option<NonEmptyMap<String, NonEmptyVec<String>>>,
}

impl KeyAuthorizations {
    /// If a namespace is present in authorized namespaces then it cannot be present in
    /// authorized data elements.
    pub fn validate(&self) -> Result<(), Error> {
        let authorized_data_elements: &NonEmptyMap<String, NonEmptyVec<String>>;

        if let Some(ds) = &self.data_elements {
            authorized_data_elements = ds;
        } else {
            return Ok(());
        }

        if let Some(authorized_namespaces) = &self.namespaces {
            authorized_namespaces.iter().try_for_each(|namespace| {
                authorized_data_elements
                    .get(namespace)
                    .map_or(Ok(()), |_| Err(Error::DoubleAuthorized(namespace.clone())))
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("namespace '{0}' cannot be present in both authorized_namespaces and authorized_data_elements")]
    DoubleAuthorized(String),
}
