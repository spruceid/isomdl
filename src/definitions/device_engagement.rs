use crate::definitions::helpers::ByteStr;
use crate::definitions::CoseKey;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;

pub type EDeviceKeyBytes = Tag24<CoseKey>;
pub type EReaderKeyBytes = Tag24<CoseKey>;

//the u64 represents a cipher suite identifier
pub type Security = (u64, EDeviceKeyBytes);
pub type DeviceRetrievalMethods = Vec<DeviceRetrievalMethod>;
// the first u64 represents a type, the second a version
pub type DeviceRetrievalMethod = (u64, u64, RetrievalOptions);
pub type ProtocolInfo = CborValue;
pub type Oidc = (u64, String, String);
pub type WebApi = (u64, String, String);
use crate::definitions::device_key::cose_key::Error as CoseKeyError;
use crate::definitions::helpers::tag24::Error as Tag24Error;
use crate::definitions::helpers::Tag24;
use anyhow::Result;
use std::{collections::BTreeMap, vec};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEngagement {
    pub version: String,
    pub security: Security,
    pub device_retrieval_methods: Option<DeviceRetrievalMethods>,
    pub server_retrieval_methods: Option<ServerRetrievalMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_info: Option<ProtocolInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RetrievalOptions {
    WIFIOPTIONS(WifiOptions),
    BLEOPTIONS(BleOptions),
    NFCOPTIONS(NfcOptions),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerRetrievalMethods {
    #[serde(skip_serializing_if = "Option::is_none")]
    web_api: Option<WebApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc: Option<Oidc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiOptions {
    pass_phrase: String,
    channel_info_operating_class: u64,
    channel_info_channel_number: u64,
    band_info: ByteStr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
                CborValue::Integer(device_engagement.security.0.into()),
                CborValue::from(device_engagement.security.1),
            ]),
        );
        if device_engagement.device_retrieval_methods.is_some() {
            let device_retrieval_method = device_engagement.device_retrieval_methods.unwrap();
            let retrieval_options = device_retrieval_method.first().unwrap().clone();

            map.insert(
                CborValue::Integer(2),
                CborValue::Array(vec![
                    CborValue::Integer(retrieval_options.0.into()),
                    CborValue::Integer(retrieval_options.1.into()),
                    CborValue::from(retrieval_options.2),
                ]),
            );
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
            let mut device_engagement = DeviceEngagement {
                version: "1.0".to_string(),
                security: (
                    0,
                    Tag24::<CoseKey>::new(CoseKey::EC2 {
                        crv: (super::EC2Curve::P256),
                        x: (vec![0]),
                        y: super::EC2Y::Value(vec![0]),
                    })?,
                ),
                device_retrieval_methods: None,
                server_retrieval_methods: None,
                protocol_info: None,
            };

            let device_engagement_version = map.remove(&CborValue::Integer(0));
            match device_engagement_version {
                Some(CborValue::Text(d)) => device_engagement.version = d,
                _ => {}
            };
            let security = map.remove(&CborValue::Integer(1));
            match security {
                Some(CborValue::Array(s)) => {
                    let u = s.first().ok_or(Error::InvalidDeviceEngagement)?.clone();
                    match u {
                        CborValue::Integer(x) => device_engagement.security.0 = x as u64,
                        _ => {}
                    }
                    let p = s.last().ok_or(Error::InvalidDeviceEngagement)?.clone();
                    match p {
                        CborValue::Bytes(key_bytes) => {
                            let cose_key = CoseKey::try_from(CborValue::Bytes(key_bytes))?;
                            device_engagement.security.1 = Tag24::<CoseKey>::new(cose_key)?;
                        }
                        _ => {}
                    }
                }
                _ => {}
            };

            let device_retrieval_method =
                map.remove(&CborValue::Integer(2)).ok_or(Error::Malformed)?;

            //only matching for supported ble_option
            match device_retrieval_method {
                CborValue::Array(mut device_retrieval) => {
                    let retrieval = device_retrieval
                        .first()
                        .ok_or(Error::InvalidDeviceEngagement)?
                        .clone();
                    match retrieval {
                        CborValue::Map(ble_options) => {}
                        CborValue::Integer(2) => {}
                        CborValue::Integer(1) => {}
                        _ => {}
                    }

                    //let transport_type = device_retrieval.remove(0);
                    //let version = device_retrieval.remove(0);
                    //let retrieval_method = device_retrieval.remove(0);
                }
                _ => {}
            }
            let server_retrieval_methods = map.remove(&CborValue::Integer(3));
            if server_retrieval_methods.is_some() {
                //throw unimplemented error
            }
            let protocol_info = map.remove(&CborValue::Integer(4));
            if protocol_info.is_some() {
                //throw warning that protocol info will be ignored by reader
            }

            Ok(device_engagement)
        } else if let CborValue::Bytes(value) = v {
            Err(Error::InvalidDeviceEngagement)
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

impl TryFrom<CborValue> for BleOptions {
    //only handles central_client BleOptions
    type Error = Error;

    fn try_from(v: CborValue) -> Result<Self, Error> {
        if let CborValue::Map(mut map) = v {
            match (
                map.remove(&CborValue::Integer(0)),
                map.remove(&CborValue::Integer(1)),
                map.remove(&CborValue::Integer(10)),
                map.remove(&CborValue::Integer(11)),
                map.remove(&CborValue::Integer(20)),
            ) {
                (
                    Some(CborValue::Bool(false)),
                    Some(CborValue::Bool(true)),
                    Some(CborValue::Bytes(server_uuid)),
                    Some(CborValue::Bytes(central_uuid)),
                    Some(CborValue::Bytes(ble_address)),
                ) => Ok(self::BleOptions {
                    peripheral_server_mode: false,
                    central_client_mode: true,
                    peripheral_server_uuid: Some(ByteStr::from(server_uuid)),
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn device_engagement_roundtrip() {}
}
