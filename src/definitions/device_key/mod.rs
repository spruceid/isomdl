//! This module contains definitions related to device keys.
//!
//! The [DeviceKeyInfo] struct represents information about a device key, including the key itself,
//! key authorizations, and additional key info.
//!
//! The [KeyAuthorizations] struct represents the authorizations for a device key, including
//! namespaces and data elements.
//!
//! # Examples
//!
//! ```ignore
//! use crate::definitions::device_key::{DeviceKeyInfo, KeyAuthorizations};
//!
//! let key_info = DeviceKeyInfo {
//!     device_key: /* initialize device key */,
//!     key_authorizations: Some(KeyAuthorizations {
//!         namespaces: Some(vec!["namespace1".to_string(), "namespace2".to_string()]),
//!         data_elements: None,
//!     }),
//!     key_info: None,
//! };
//! ```
//!
//! # Errors
//!
//! The [Error] enum represents the possible errors that can occur when validating key authorizations.
//!
//! - [Error::DoubleAuthorized] indicates that a namespace is present in both `authorized_namespaces` and `authorized_data_elements`.
//!
//! # Examples
//!
//! ```ignore
//! use crate::definitions::device_key::{KeyAuthorizations, Error};
//!
//! let key_auth = KeyAuthorizations {
//!     namespaces: Some(vec!["namespace1".to_string(), "namespace2".to_string()]),
//!     data_elements: Some(Default::default()),
//! };
//!
//! let result = key_auth.validate();
//! assert!(result.is_err());
//! assert_eq!(result.unwrap_err(), Error::DoubleAuthorized("namespace1".to_string()));
//! ```
use crate::definitions::helpers::{NonEmptyMap, NonEmptyVec};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::collections::BTreeMap;

pub mod cose_key;
pub use cose_key::CoseKey;
pub use cose_key::EC2Curve;

/// Represents information about a device key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    /// The device key.
    pub device_key: CoseKey,

    /// Optional key authorizations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_authorizations: Option<KeyAuthorizations>,

    /// Optional key information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_info: Option<BTreeMap<i128, CborValue>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorizations {
    /// The namespaces associated with the key. This field is optional and will
    /// be skipped during serialization if it is [None].
    #[serde(skip_serializing_if = "Option::is_none", rename = "nameSpaces")]
    pub namespaces: Option<NonEmptyVec<String>>,

    /// The data elements associated with the key. This field is optional and will
    /// be skipped during serialization if it is [None].
    pub data_elements: Option<NonEmptyMap<String, NonEmptyVec<String>>>,
}

impl KeyAuthorizations {
    /// If a namespace is present in authorized namespaces, then it cannot be present in
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

    /// Determine whether the key is permitted to sign over the designated element.
    pub fn permitted(&self, namespace: &String, element_identifier: &String) -> bool {
        if let Some(namespaces) = self.namespaces.as_ref() {
            return namespaces.contains(namespace);
        }
        if let Some(namespaces) = self.data_elements.as_ref() {
            if let Some(data_elements) = namespaces.get(namespace).as_ref() {
                return data_elements.contains(element_identifier);
            }
        }
        false
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("namespace '{0}' cannot be present in both authorized_namespaces and authorized_data_elements")]
    DoubleAuthorized(String),
}
