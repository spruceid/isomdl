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

use std::collections::BTreeMap;

use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use isomdl_macros::FieldsNames;

pub use cose_key::CoseKey;
pub use cose_key::EC2Curve;

use crate::cbor::CborValue;
use crate::definitions::helpers::string_cbor::CborString;
use crate::definitions::helpers::{NonEmptyMap, NonEmptyVec};

pub mod cose_key;
/// Represents information about a device key.
#[derive(Clone, Debug, FieldsNames)]
#[isomdl(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    /// The device key.
    pub device_key: CoseKey,

    /// Optional key authorizations.
    #[isomdl(skip_serializing_if = "Option::is_none")]
    pub key_authorizations: Option<KeyAuthorizations>,

    /// Optional key information.
    #[isomdl(skip_serializing_if = "Option::is_none")]
    pub key_info: Option<BTreeMap<CborValue, CborValue>>,
}

impl CborSerializable for DeviceKeyInfo {}
impl AsCborValue for DeviceKeyInfo {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map: BTreeMap<CborValue, CborValue> = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "DeviceKeyInfo is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        Ok(DeviceKeyInfo {
            device_key: map
                .remove(&DeviceKeyInfo::fn_device_key().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "device_key is missing".to_string()),
                ))?
                .try_into()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "device_key is not a CoseKey".to_string(),
                    ))
                })?,
            key_authorizations: None,
            key_info: None,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![];
        map.push((
            Value::Text(DeviceKeyInfo::fn_device_key().to_string()),
            self.device_key.to_cbor_value()?,
        ));
        if let Some(key_authorizations) = self.key_authorizations {
            map.push((
                Value::Text(DeviceKeyInfo::fn_key_authorizations().to_string()),
                key_authorizations.to_cbor_value()?,
            ));
        }
        if let Some(key_info) = self.key_info {
            let key_info: NonEmptyMap<CborValue, CborValue> = key_info.into_iter().collect();
            map.push((
                Value::Text(DeviceKeyInfo::fn_key_info().to_string()),
                key_info.to_cbor_value()?,
            ));
        }
        Ok(Value::Map(map))
    }
}

#[derive(Clone, FieldsNames, Debug, Default)]
#[isomdl(rename_all = "camelCase")]
pub struct KeyAuthorizations {
    /// The namespaces associated with the key. This field is optional and will
    /// be skipped during serialization if it is [None].
    #[isomdl(skip_serializing_if = "Option::is_none", rename = "nameSpaces")]
    pub namespaces: Option<NonEmptyVec<CborString>>,

    /// The data elements associated with the key. This field is optional and will
    /// be skipped during serialization if it is [None].
    #[isomdl(skip_serializing_if = "Option::is_none")]
    pub data_elements: Option<NonEmptyMap<CborString, NonEmptyVec<CborString>>>,
}

impl CborSerializable for KeyAuthorizations {}
impl AsCborValue for KeyAuthorizations {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map: BTreeMap<CborValue, CborValue> = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "KeyAuthorizations is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(KeyAuthorizations {
            namespaces: map
                .remove(&KeyAuthorizations::fn_namespaces().into())
                .map(|v| NonEmptyVec::from_cbor_value(v.into()))
                .transpose()?,
            data_elements: map
                .remove(&KeyAuthorizations::fn_data_elements().into())
                .map(|v| NonEmptyMap::from_cbor_value(v.into()))
                .transpose()?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![];
        if let Some(namespaces) = self.namespaces {
            map.push((
                KeyAuthorizations::fn_namespaces().into(),
                namespaces.to_cbor_value()?,
            ));
        }
        if let Some(data_elements) = self.data_elements {
            map.push((
                KeyAuthorizations::fn_data_elements().into(),
                data_elements.to_cbor_value()?,
            ));
        }
        Ok(Value::Map(map))
    }
}

impl KeyAuthorizations {
    /// If a namespace is present in authorized namespaces, then it cannot be present in
    /// authorized data elements.
    pub fn validate(&self) -> Result<(), Error> {
        let authorized_data_elements: &NonEmptyMap<CborString, NonEmptyVec<CborString>>;

        if let Some(ds) = &self.data_elements {
            authorized_data_elements = ds;
        } else {
            return Ok(());
        }

        if let Some(authorized_namespaces) = &self.namespaces {
            authorized_namespaces.iter().try_for_each(|namespace| {
                authorized_data_elements.get(namespace).map_or(Ok(()), |_| {
                    Err(Error::DoubleAuthorized(namespace.clone().into()))
                })
            })
        } else {
            Ok(())
        }
    }

    /// Determine whether the key is permitted to sign over the designated element.
    pub fn permitted(&self, namespace: &String, element_identifier: &String) -> bool {
        if let Some(namespaces) = self.namespaces.as_ref() {
            return namespaces.contains(&namespace.into());
        }
        if let Some(namespaces) = self.data_elements.as_ref() {
            if let Some(data_elements) = namespaces.get(&namespace.into()).as_ref() {
                return data_elements.contains(&element_identifier.into());
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
