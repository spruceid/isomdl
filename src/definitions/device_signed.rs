//! This module contains the definitions related to device signing.
//!
//! The [DeviceSigned] struct represents a device signed object, which includes namespaces and device authentication information.
//!
//! The [Error] enum represents the possible errors that can occur in this module.
//! - [Error::UnableToEncode]: Indicates an error when encoding a value as CBOR.
use crate::cose::mac0::CoseMac0;
use crate::cose::sign1::CoseSign1;
use crate::cose::{ciborium_value_into_serde_cbor_value, serde_cbor_value_into_ciborium_value};
use crate::definitions::{
    helpers::{NonEmptyMap, Tag24},
    session::SessionTranscript,
};
use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use serde::{Deserialize, Serialize};
use serde_cbor::{Error as CborError, Value as CborValue};
use std::collections::BTreeMap;
use strum_macros::{AsRefStr, EnumVariantNames};

/// Represents a device-signed structure.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSigned {
    #[serde(rename = "nameSpaces")]
    /// A [DeviceNamespacesBytes] struct representing the namespaces.
    pub namespaces: DeviceNamespacesBytes,

    /// A [DeviceAuth] struct representing the device authentication.
    pub device_auth: DeviceAuth,
}

pub type DeviceNamespacesBytes = Tag24<DeviceNamespaces>;
pub type DeviceNamespaces = BTreeMap<String, DeviceSignedItems>;
pub type DeviceSignedItems = NonEmptyMap<String, CborValue>;

struct DeviceNamespaces2(DeviceNamespaces);

/// Represents a device signature.
///
/// This struct contains the device signature in the form of a [CoseSign1] object.
/// The [CoseSign1] object represents a `COSE (CBOR Object Signing and Encryption) signature.
#[derive(Clone, Debug, Deserialize, Serialize, EnumVariantNames, AsRefStr)]
#[serde(untagged)]
pub enum DeviceAuth {
    #[serde(rename_all = "camelCase")]
    Signature { device_signature: CoseSign1 },
    #[serde(rename_all = "camelCase")]
    Mac { device_mac: CoseMac0 },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceAuthType {
    #[serde(rename_all = "camelCase")]
    Sign1,
    #[serde(rename_all = "camelCase")]
    Mac0,
}

pub type DeviceAuthenticationBytes<S> = Tag24<DeviceAuthentication<S>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceAuthentication<S: SessionTranscript>(
    &'static str,
    // See https://github.com/serde-rs/serde/issues/1296.
    #[serde(bound = "")] S,
    String,
    DeviceNamespacesBytes,
);

impl<S: SessionTranscript> DeviceAuthentication<S> {
    pub fn new(transcript: S, doc_type: String, namespaces_bytes: DeviceNamespacesBytes) -> Self {
        Self(
            "DeviceAuthentication",
            transcript,
            doc_type,
            namespaces_bytes,
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unable to encode value as CBOR: {0}")]
    UnableToEncode(CborError),
}

impl coset::CborSerializable for DeviceAuth {}
impl AsCborValue for DeviceAuth {
    fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
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

    fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
        Ok(ciborium::Value::Map(
            vec![(
                ciborium::Value::Text(self.as_ref().to_string()),
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

impl coset::CborSerializable for DeviceSigned {}
impl AsCborValue for DeviceSigned {
    fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
        let mut arr = value.into_array().map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "not an array".to_string(),
            ))
        })?;
        Ok(DeviceSigned {
            namespaces: cbor_value_to_device_namespaces_bytes(arr.remove(0))?,
            device_auth: DeviceAuth::from_cbor_value(arr.remove(0))?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Array(
            vec![
                device_namespaces_bytes_to_cbor_value(self.namespaces)?,
                self.device_auth.to_cbor_value()?,
            ]
            .into_iter()
            .collect(),
        ))
    }
}

impl CborSerializable for DeviceNamespaces2 {}
impl AsCborValue for DeviceNamespaces2 {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        Ok(DeviceNamespaces2(
            value
                .into_map()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "unknown key".to_string(),
                    ))
                })?
                .into_iter()
                .map(|(k, v)| {
                    let key = k.into_text().map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "not a text".to_string(),
                        ))
                    })?;
                    let value = v
                        .into_map()
                        .map_err(|_| {
                            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                None,
                                "not a map".to_string(),
                            ))
                        })
                        .map(|v| {
                            v.into_iter()
                                .map(|(k, v)| {
                                    let k = k.into_text().map_err(|_| {
                                        coset::CoseError::DecodeFailed(
                                            ciborium::de::Error::Semantic(
                                                None,
                                                "not a text".to_string(),
                                            ),
                                        )
                                    })?;
                                    let v = ciborium_value_into_serde_cbor_value(v)?;
                                    Ok::<(String, CborValue), coset::CoseError>((k, v))
                                })
                                .collect::<Result<DeviceSignedItems, coset::CoseError>>()
                        })?;
                    Ok::<(String, DeviceSignedItems), coset::CoseError>((key, value?))
                })
                .collect::<Result<DeviceNamespaces, coset::CoseError>>()?,
        ))
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(
            self.0
                .into_iter()
                .map(|(k, v)| {
                    let key = Value::Text(k);
                    let value = Value::Map(
                        v.into_inner()
                            .into_iter()
                            .map(|(k, v)| {
                                let key = Value::Text(k);
                                let value = serde_cbor_value_into_ciborium_value(v)?;
                                Ok((key, value))
                            })
                            .collect::<Result<Vec<(Value, Value)>, coset::CoseError>>()?,
                    );
                    Ok::<(Value, Value), coset::CoseError>((key, value))
                })
                .collect::<Result<Vec<(Value, Value)>, coset::CoseError>>()?,
        ))
    }
}

fn device_namespaces_bytes_to_cbor_value(val: DeviceNamespacesBytes) -> coset::Result<Value> {
    let device_namespaces = Value::Map(
        val.into_inner()
            .into_iter()
            .flat_map(|(k, v)| {
                let key = Value::Text(k);
                let value = Value::Map(
                    v.into_inner()
                        .into_iter()
                        .flat_map(|(k, v)| {
                            let key = Value::Text(k);
                            let value = serde_cbor_value_into_ciborium_value(v)?;
                            Ok::<(Value, Value), coset::CoseError>((key, value))
                        })
                        .collect::<Vec<(Value, Value)>>(),
                );
                Ok::<(Value, Value), coset::CoseError>((key, value))
            })
            .collect::<Vec<(Value, Value)>>(),
    );
    Ok(Value::Tag(
        24,
        Box::new(Value::Bytes(device_namespaces.to_vec()?)),
    ))
}

fn cbor_value_to_device_namespaces_bytes(val: Value) -> coset::Result<DeviceNamespacesBytes> {
    if let Value::Tag(24, inner_value) = val {
        if let Value::Bytes(inner_bytes) = *inner_value {
            let inner: DeviceNamespaces2 = CborSerializable::from_slice(&inner_bytes)?;
            Ok(Tag24::new(inner.0).map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "invalid inner bytes".to_string(),
                ))
            })?)
        } else {
            Err(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "invalid inner bytes".to_string()),
            ))
        }
    } else {
        Err(coset::CoseError::DecodeFailed(
            ciborium::de::Error::Semantic(None, "not tag 24".to_string()),
        ))
    }
}
