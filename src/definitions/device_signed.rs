//! This module contains the definitions related to device signing.
//!
//! The [DeviceSigned] struct represents a device signed object, which includes namespaces and device authentication information.
//!
//! The [Error] enum represents the possible errors that can occur in this module.
//! - [Error::UnableToEncode]: Indicates an error when encoding a value as CBOR.
use std::collections::HashMap;

use crate::cose::mac0::CoseMac0;
use crate::cose::sign1::CoseSign1;
use crate::definitions::helpers::b_tree_map_string_cbor::BTreeMapCbor;
use crate::definitions::helpers::string_cbor::CborString;
use crate::definitions::{
    helpers::{NonEmptyMap, Tag24},
    session::SessionTranscript,
};
use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use isomdl_macros::FieldsNames;
use serde::{Deserialize, Serialize};
use strum_macros::AsRefStr;

/// Represents a device-signed structure.
#[derive(Clone, Debug, FieldsNames)]
#[isomdl(rename_all = "camelCase")]
pub struct DeviceSigned {
    #[isomdl(rename = "nameSpaces")]
    /// A [DeviceNamespacesBytes] struct representing the namespaces.
    pub namespaces: DeviceNamespacesBytes,

    /// A [DeviceAuth] struct representing the device authentication.
    pub device_auth: DeviceAuth,
}

pub type DeviceNamespacesBytes = Tag24<DeviceNamespaces>;
pub type DeviceNamespaces = BTreeMapCbor<CborString, DeviceSignedItems>;
pub type DeviceSignedItems = NonEmptyMap<CborString, Value>;

/// Represents a device signature.
///
/// This struct contains the device signature in the form of a [CoseSign1] object.
/// The [CoseSign1] object represents a `COSE (CBOR Object Signing and Encryption) signature.
#[derive(Clone, Debug, AsRefStr)]
pub enum DeviceAuth {
    Signature { device_signature: CoseSign1 },
    Mac { device_mac: CoseMac0 },
}

#[derive(Debug, Clone, Copy, FieldsNames)]
pub enum DeviceAuthType {
    Sign1,
    Mac0,
}

impl CborSerializable for DeviceAuthType {}
impl AsCborValue for DeviceAuthType {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        Ok(match value {
            Value::Text(s) => match s.as_str() {
                "sign1" => DeviceAuthType::Sign1,
                "mac0" => DeviceAuthType::Mac0,
                _ => {
                    return Err(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, "unknown device auth type".to_string()),
                    ))
                }
            },
            _ => {
                return Err(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "not a text".to_string()),
                ))
            }
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(match self {
            DeviceAuthType::Sign1 => Value::Text(DeviceAuthType::fn_sign1().to_string()),
            DeviceAuthType::Mac0 => Value::Text(DeviceAuthType::fn_mac0().to_string()),
        })
    }
}

pub type DeviceAuthenticationBytes<S> = Tag24<DeviceAuthentication<S>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceAuthentication<S: SessionTranscript>(
    String,
    // See https://github.com/serde-rs/serde/issues/1296.
    #[serde(bound = "")] S,
    String,
    DeviceNamespacesBytes,
);

impl<S: SessionTranscript> CborSerializable for DeviceAuthentication<S> {}
impl<S: SessionTranscript> AsCborValue for DeviceAuthentication<S> {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut arr = value.into_array().map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "not an array".to_string(),
            ))
        })?;
        if arr.len() != 4 {
            return Err(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "wrong number of items".to_string()),
            ));
        }
        Ok(DeviceAuthentication(
            arr.remove(0).into_text().map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "not a text".to_string(),
                ))
            })?,
            S::from_cbor_value(arr.remove(0))?,
            arr.remove(0).into_text().map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "not a text".to_string(),
                ))
            })?,
            DeviceNamespacesBytes::from_cbor_value(arr.remove(0))?,
        ))
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Array(vec![
            Value::Text(self.0),
            self.1.to_cbor_value()?,
            Value::Text(self.2),
            self.3.to_cbor_value()?,
        ]))
    }
}

impl<S: SessionTranscript> DeviceAuthentication<S> {
    pub fn new(transcript: S, doc_type: String, namespaces_bytes: DeviceNamespacesBytes) -> Self {
        Self(
            "DeviceAuthentication".to_string(),
            transcript,
            doc_type,
            namespaces_bytes,
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unable to encode value as CBOR: {0}")]
    UnableToEncode(coset::CoseError),
}

impl CborSerializable for DeviceAuth {}
impl AsCborValue for DeviceAuth {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "not a map".to_string(),
                ))
            })?
            .into_iter()
            .flat_map(|(k, v)| {
                let k = k.as_text().ok_or_else(|| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "not a text".to_string(),
                    ))
                })?;
                match k {
                    "deviceSignature" => Ok(DeviceAuth::Signature {
                        device_signature: CoseSign1::from_cbor_value(v)?,
                    }),
                    "deviceMac" => Ok(DeviceAuth::Mac {
                        device_mac: CoseMac0::from_cbor_value(v)?,
                    }),
                    _ => Err(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, "unknown key".to_string()),
                    )),
                }
            })
            .next()
            .ok_or_else(|| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "empty map".to_string(),
                ))
            })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let key = match self {
            DeviceAuth::Signature { .. } => "deviceSignature",
            DeviceAuth::Mac { .. } => "deviceMac",
        };
        Ok(Value::Map(
            vec![(
                Value::Text(key.to_string()),
                match self {
                    DeviceAuth::Signature { device_signature } => {
                        device_signature.to_cbor_value()?
                    }
                    DeviceAuth::Mac { device_mac } => device_mac.to_cbor_value()?,
                },
            )]
            .into_iter()
            .collect(),
        ))
    }
}

impl CborSerializable for DeviceSigned {}
impl AsCborValue for DeviceSigned {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut fields = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "DeviceSigned is not a map".to_string(),
                ))
            })?
            .into_iter()
            .flat_map(|f| match f.0 {
                Value::Text(s) => Ok::<(String, Value), coset::CoseError>((s, f.1)),
                _ => Err(coset::CoseError::UnexpectedItem(
                    "key",
                    "text for field in DeviceSigned",
                )),
            })
            .collect::<HashMap<String, Value>>();
        Ok(DeviceSigned {
            namespaces: DeviceNamespacesBytes::from_cbor_value(
                fields.remove(DeviceSigned::fn_namespaces()).ok_or(
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "DeviceSigned::namespaces is missing".to_string(),
                    )),
                )?,
            )?,
            device_auth: DeviceAuth::from_cbor_value(
                fields.remove(DeviceSigned::fn_device_auth()).ok_or(
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "DeviceSigned::device_auth is missing".to_string(),
                    )),
                )?,
            )?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(
            vec![
                (
                    Value::Text(DeviceSigned::fn_namespaces().to_string()),
                    self.namespaces.to_cbor_value()?,
                ),
                (
                    Value::Text(DeviceSigned::fn_device_auth().to_string()),
                    self.device_auth.to_cbor_value()?,
                ),
            ]
            .into_iter()
            .collect(),
        ))
    }
}
