use crate::definitions::helpers::ByteStr;
use crate::definitions::CoseKey;
use serde::{Deserialize, Serialize};
use serde_cbor::Error as SerdeCborError;
use serde_cbor::Value as CborValue;

pub type EDeviceKeyBytes = Tag24<CoseKey>;
pub type EReaderKeyBytes = Tag24<CoseKey>;

pub type DeviceRetrievalMethods = Vec<DeviceRetrievalMethod>;
pub type ProtocolInfo = CborValue;
pub type Oidc = (u64, String, String);
pub type WebApi = (u64, String, String);
use crate::definitions::device_key::cose_key::Error as CoseKeyError;
use crate::definitions::helpers::tag24::Error as Tag24Error;
use crate::definitions::helpers::Tag24;
use anyhow::Result;
use std::{collections::BTreeMap, vec};

use super::{EC2Curve, EC2Y};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "CborValue", into = "CborValue", rename_all = "camelCase")]
pub struct DeviceEngagement {
    pub version: String,
    pub security: Security,
    pub device_retrieval_methods: Option<DeviceRetrievalMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_retrieval_methods: Option<ServerRetrievalMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_info: Option<ProtocolInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DeviceRetrievalMethod {
    pub transport_type: u64,
    pub version: u64,
    pub retrieval_method: RetrievalOptions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Security {
    pub cipher_suite_identifier: u64,
    pub e_device_key_bytes: EDeviceKeyBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum RetrievalOptions {
    WIFIOPTIONS(WifiOptions),
    BLEOPTIONS(BleOptions),
    NFCOPTIONS(NfcOptions),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServerRetrievalMethods {
    #[serde(skip_serializing_if = "Option::is_none")]
    web_api: Option<WebApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc: Option<Oidc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(try_from = "CborValue", rename_all = "camelCase")]
pub struct BleOptions {
    pub peripheral_server_mode: bool,
    pub central_client_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peripheral_server_uuid: Option<ByteStr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_central_uuid: Option<ByteStr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mdoc_ble_device_address_peripheral_server: Option<ByteStr>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WifiOptions {
    pass_phrase: String,
    channel_info_operating_class: u64,
    channel_info_channel_number: u64,
    band_info: ByteStr,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NfcOptions {
    max_len_command_data_field: u64,
    max_len_response_data_field: u64,
}

/// Errors that can occur when deserialising a DeviceEngagement.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Unimplemented BLE option")]
    Unimplemented,
    #[error("Invalid DeviceEngagment found")]
    InvalidDeviceEngagement,
    #[error("Malformed object not recognised")]
    Malformed,
    #[error("Something went wrong parsing a cose key")]
    CoseKeyError,
    #[error("Something went wrong parsing a tag24")]
    Tag24Error,
    #[error("Could not deserialize from cbor")]
    SerdeCborError,
}

impl From<CoseKeyError> for Error {
    fn from(_: CoseKeyError) -> Self {
        Error::CoseKeyError
    }
}

impl From<Tag24Error> for Error {
    fn from(_: Tag24Error) -> Self {
        Error::Tag24Error
    }
}

impl From<SerdeCborError> for Error {
    fn from(_: SerdeCborError) -> Self {
        Error::SerdeCborError
    }
}

impl From<DeviceEngagement> for CborValue {
    fn from(device_engagement: DeviceEngagement) -> CborValue {
        let mut map = BTreeMap::new();
        map.insert(
            CborValue::Integer(0),
            CborValue::Text(device_engagement.version),
        );
        map.insert(
            CborValue::Integer(1),
            CborValue::Array(vec![
                CborValue::Integer(device_engagement.security.cipher_suite_identifier.into()),
                CborValue::from(device_engagement.security.e_device_key_bytes),
            ]),
        );
        if device_engagement.device_retrieval_methods.is_some() {
            let device_retrieval_method = device_engagement
                .device_retrieval_methods
                .ok_or(Error::Malformed);
            //TODO fix unwrap
            let retrieval_options = device_retrieval_method.unwrap().first().unwrap().clone();

            map.insert(CborValue::Integer(2), CborValue::from(retrieval_options));
        }
        // Server retrieval not implemented and should always be none
        if device_engagement.server_retrieval_methods.is_some() {
            map.insert(CborValue::Integer(3), CborValue::Null);
        }
        // Usage of protocolinfo is RFU and should for now be none
        if device_engagement.protocol_info.is_some() {
            map.insert(CborValue::Integer(4), CborValue::Null);
        }

        CborValue::Map(map)
    }
}

impl TryFrom<CborValue> for DeviceEngagement {
    type Error = Error;
    fn try_from(v: CborValue) -> Result<Self, Error> {
        if let CborValue::Map(mut map) = v {
            let device_engagement_version = map.remove(&CborValue::Integer(0));
            let mut version: String = "".to_string();
            match device_engagement_version {
                Some(CborValue::Text(v)) => version = v,
                _ => {}
            };
            let device_engagement_security =
                map.remove(&CborValue::Integer(1)).ok_or(Error::Malformed)?;

            let security: Security = Security::try_from(device_engagement_security)?;

            //only matching for supported ble_option
            let device_retrieval_method = DeviceRetrievalMethod::try_from(
                map.remove(&CborValue::Integer(2)).ok_or(Error::Malformed)?,
            )?;

            let device_retrieval_methods: DeviceRetrievalMethods = vec![device_retrieval_method];

            let server_retrieval_methods = map.remove(&CborValue::Integer(3));
            if server_retrieval_methods.is_some() {
                tracing::warn!("server_retrieval is unimplemented.")
            }
            let protocol_info = map.remove(&CborValue::Integer(4));
            if protocol_info.is_some() {
                tracing::warn!("protocol_info is RFU and has been ignored in deserialization.")
            }

            let device_engagement = DeviceEngagement {
                version: version,
                security: security,
                device_retrieval_methods: Some(device_retrieval_methods),
                server_retrieval_methods: None,
                protocol_info: None,
            };

            Ok(device_engagement)
        } else {
            Err(Error::InvalidDeviceEngagement)
        }
    }
}

impl From<RetrievalOptions> for CborValue {
    fn from(retrieval_option: RetrievalOptions) -> Self {
        match retrieval_option {
            RetrievalOptions::BLEOPTIONS(ble_options) => {
                let mut map = BTreeMap::<CborValue, CborValue>::new();
                // peripheral_server_mode: 0
                map.insert(
                    CborValue::Integer(0),
                    CborValue::Bool(ble_options.peripheral_server_mode),
                );
                // client_mode: 1
                map.insert(
                    CborValue::Integer(1),
                    CborValue::Bool(ble_options.central_client_mode),
                );
                // server_uuid: 10
                if ble_options.peripheral_server_uuid.is_some() {
                    map.insert(
                        CborValue::Integer(10),
                        CborValue::from(ble_options.peripheral_server_uuid.unwrap()),
                    );
                };
                // client_uuid: 11
                if ble_options.client_central_uuid.is_some() {
                    map.insert(
                        CborValue::Integer(11),
                        CborValue::from(ble_options.client_central_uuid.unwrap()),
                    );
                }
                // ble_device_address: 20
                if ble_options
                    .mdoc_ble_device_address_peripheral_server
                    .is_some()
                {
                    map.insert(
                        CborValue::Integer(20),
                        CborValue::from(
                            ble_options
                                .mdoc_ble_device_address_peripheral_server
                                .unwrap(),
                        ),
                    );
                }

                CborValue::Map(map)
            }
            RetrievalOptions::WIFIOPTIONS(wifi_options) => {
                let mut map = BTreeMap::<CborValue, CborValue>::new();
                map.insert(
                    CborValue::Integer(0),
                    CborValue::Text(wifi_options.pass_phrase),
                );
                map.insert(
                    CborValue::Integer(1),
                    CborValue::Integer(wifi_options.channel_info_operating_class.into()),
                );
                map.insert(
                    CborValue::Integer(2),
                    CborValue::Integer(wifi_options.channel_info_channel_number.into()),
                );
                map.insert(
                    CborValue::Integer(3),
                    CborValue::from(wifi_options.band_info),
                );

                CborValue::Map(map)
            }
            RetrievalOptions::NFCOPTIONS(nfc_options) => {
                let mut map = BTreeMap::<CborValue, CborValue>::new();
                map.insert(
                    CborValue::Integer(0),
                    CborValue::Integer(nfc_options.max_len_command_data_field.into()),
                );
                map.insert(
                    CborValue::Integer(1),
                    CborValue::Integer(nfc_options.max_len_response_data_field.into()),
                );

                CborValue::Map(map)
            }
        }
    }
}

impl TryFrom<CborValue> for DeviceRetrievalMethod {
    type Error = Error;
    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        if let CborValue::Array(mut list) = value {
            match (list.remove(0), list.remove(0), list.remove(0)) {
                (
                    CborValue::Integer(2),
                    CborValue::Integer(1),
                    CborValue::Map(retrieval_methods),
                ) => {
                    let ble_option = BleOptions::try_from(CborValue::Map(retrieval_methods))?;
                    let device_retrieval_method = DeviceRetrievalMethod {
                        transport_type: 2,
                        version: 1,
                        retrieval_method: RetrievalOptions::BLEOPTIONS(ble_option),
                    };
                    Ok(device_retrieval_method)
                }
                _ => Err(Error::Malformed),
            }
        } else {
            Err(Error::Malformed)
        }
    }
}

impl From<DeviceRetrievalMethod> for CborValue {
    fn from(drm: DeviceRetrievalMethod) -> Self {
        let transport_type = CborValue::Integer(drm.transport_type.into());
        let version = CborValue::Integer(drm.version.into());
        let retrieval_method = CborValue::from(drm.retrieval_method);
        CborValue::Array(vec![transport_type, version, retrieval_method])
    }
}

impl TryFrom<CborValue> for Security {
    type Error = Error;
    fn try_from(device_engagement_security: CborValue) -> Result<Self, Self::Error> {
        match device_engagement_security {
            CborValue::Array(sec) => {
                let mut id: u64 = 0;
                let cipher_suite_identifier =
                    sec.first().ok_or(Error::InvalidDeviceEngagement)?.clone();
                match cipher_suite_identifier {
                    CborValue::Integer(x) => id = x as u64,
                    _ => {}
                }
                let mdoc_public_key = sec.last().ok_or(Error::InvalidDeviceEngagement)?.clone();

                let mut key = Tag24::<CoseKey>::new(CoseKey::EC2 {
                    crv: (EC2Curve::P256),
                    x: (vec![0]),
                    y: (EC2Y::Value(vec![1])),
                })?;

                match mdoc_public_key {
                    CborValue::Tag(_tag, key_bytes) => match *key_bytes {
                        CborValue::Bytes(bytes) => {
                            let cose_key = serde_cbor::from_slice(bytes.as_ref())?;
                            key = Tag24::<CoseKey>::new(cose_key)?;
                        }
                        _ => {}
                    },
                    _ => {}
                }

                let security = Security {
                    cipher_suite_identifier: id,
                    e_device_key_bytes: key,
                };
                Ok(security)
            }
            _ => Err(Error::Malformed),
        }
    }
}

impl TryFrom<CborValue> for BleOptions {
    //only handles central_client BleOptions
    type Error = Error;

    fn try_from(v: CborValue) -> Result<Self, Error> {
        if let CborValue::Map(mut map) = v {
            match (
                map.remove(&CborValue::Integer(0)),
                map.remove(&CborValue::Integer(1)),
                map.remove(&CborValue::Integer(11)),
                map.remove(&CborValue::Integer(20)),
            ) {
                (
                    Some(CborValue::Bool(false)),
                    Some(CborValue::Bool(true)),
                    Some(CborValue::Bytes(central_uuid)),
                    Some(CborValue::Bytes(ble_address)),
                ) => Ok(self::BleOptions {
                    peripheral_server_mode: false,
                    central_client_mode: true,
                    peripheral_server_uuid: None,
                    client_central_uuid: Some(ByteStr::from(central_uuid)),
                    mdoc_ble_device_address_peripheral_server: Some(ByteStr::from(ble_address)),
                }),
                _ => Err(Error::Unimplemented),
            }
        } else {
            Err(Error::Unimplemented)
        }
    }
}
