use crate::definitions::device_key::cose_key::Error as CoseKeyError;
use crate::definitions::helpers::tag24::Error as Tag24Error;
use crate::definitions::helpers::Tag24;
use crate::definitions::helpers::{ByteStr, NonEmptyVec};
use crate::definitions::CoseKey;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_cbor::Error as SerdeCborError;
use serde_cbor::Value as CborValue;
use std::{collections::BTreeMap, vec};
use uuid::Uuid;

pub type EDeviceKeyBytes = Tag24<CoseKey>;
pub type EReaderKeyBytes = Tag24<CoseKey>;

pub type DeviceRetrievalMethods = NonEmptyVec<DeviceRetrievalMethod>;
pub type ProtocolInfo = CborValue;
pub type Oidc = (u64, String, String);
pub type WebApi = (u64, String, String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub enum DeviceRetrievalMethod {
    WIFI(WifiOptions),
    BLE(BleOptions),
    NFC(NfcOptions),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Security(pub u64, pub EDeviceKeyBytes);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerRetrievalMethods {
    #[serde(skip_serializing_if = "Option::is_none")]
    web_api: Option<WebApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc: Option<Oidc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub struct BleOptions {
    pub peripheral_server_mode: Option<PeripheralServerMode>,
    pub central_client_mode: Option<CentralClientMode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeripheralServerMode {
    pub uuid: Uuid,
    pub ble_device_address: Option<ByteStr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CentralClientMode {
    pub uuid: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub struct WifiOptions {
    pass_phrase: Option<String>,
    channel_info_operating_class: Option<u64>,
    channel_info_channel_number: Option<u64>,
    band_info: Option<ByteStr>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub struct NfcOptions {
    max_len_command_data_field: u64,
    max_len_response_data_field: u64,
}

// TODO: Add more context to errors.
/// Errors that can occur when deserialising a DeviceEngagement.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Expected isomdl version 1.0")]
    UnsupportedVersion,
    #[error("Unsupported device retrieval method")]
    UnsupportedDRM,
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
                device_engagement.security.0.into(),
                device_engagement.security.1.into(),
            ]),
        );
        if let Some(methods) = device_engagement.device_retrieval_methods {
            let methods = Vec::from(methods).into_iter().map(Into::into).collect();
            map.insert(CborValue::Integer(2), CborValue::Array(methods));
        }
        if let Some(methods) = device_engagement.server_retrieval_methods {
            map.insert(CborValue::Integer(3), methods.into());
        }
        if let Some(_info) = device_engagement.protocol_info {
            // Usage of protocolinfo is RFU and should for now be none
        }

        CborValue::Map(map)
    }
}

impl TryFrom<CborValue> for DeviceEngagement {
    type Error = Error;
    fn try_from(v: CborValue) -> Result<Self, Error> {
        if let CborValue::Map(mut map) = v {
            let device_engagement_version = map.remove(&CborValue::Integer(0));
            if let Some(CborValue::Text(v)) = device_engagement_version {
                if v != "1.0" {
                    return Err(Error::UnsupportedVersion);
                }
            } else {
                return Err(Error::Malformed);
            }
            let device_engagement_security =
                map.remove(&CborValue::Integer(1)).ok_or(Error::Malformed)?;

            let security: Security = serde_cbor::value::from_value(device_engagement_security)
                .map_err(|_| Error::Malformed)?;

            let device_retrieval_methods = map
                .remove(&CborValue::Integer(2))
                .map(serde_cbor::value::from_value)
                .transpose()
                .map_err(|_| Error::Malformed)?;

            let server_retrieval_methods = map
                .remove(&CborValue::Integer(3))
                .map(serde_cbor::value::from_value)
                .transpose()
                .map_err(|_| Error::Malformed)?;
            if server_retrieval_methods.is_some() {
                tracing::warn!("server_retrieval is unimplemented.")
            }
            let protocol_info = map.remove(&CborValue::Integer(4));
            if protocol_info.is_some() {
                tracing::warn!("protocol_info is RFU and has been ignored in deserialization.")
            }

            let device_engagement = DeviceEngagement {
                version: "1.0".into(),
                security,
                device_retrieval_methods,
                server_retrieval_methods,
                protocol_info,
            };

            Ok(device_engagement)
        } else {
            Err(Error::InvalidDeviceEngagement)
        }
    }
}

impl DeviceRetrievalMethod {
    pub fn version(&self) -> u64 {
        1
    }

    pub fn transport_type(&self) -> u64 {
        match self {
            Self::NFC(_) => 1,
            Self::BLE(_) => 2,
            Self::WIFI(_) => 3,
        }
    }
}

impl TryFrom<CborValue> for DeviceRetrievalMethod {
    type Error = Error;
    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        if let CborValue::Array(list) = value {
            let method: [CborValue; 3] = list.try_into().map_err(|_| Error::Malformed)?;
            match method {
                [CborValue::Integer(1), CborValue::Integer(1), methods] => {
                    let nfc_options = NfcOptions::try_from(methods)?;
                    Ok(DeviceRetrievalMethod::NFC(nfc_options))
                }
                [CborValue::Integer(2), CborValue::Integer(1), methods] => {
                    let ble_options = BleOptions::try_from(methods)?;
                    Ok(DeviceRetrievalMethod::BLE(ble_options))
                }
                [CborValue::Integer(3), CborValue::Integer(1), methods] => {
                    let wifi_options = WifiOptions::try_from(methods)?;
                    Ok(DeviceRetrievalMethod::WIFI(wifi_options))
                }
                [CborValue::Integer(_), _, _] => Err(Error::UnsupportedDRM),
                _ => Err(Error::Malformed),
            }
        } else {
            Err(Error::Malformed)
        }
    }
}

impl From<DeviceRetrievalMethod> for CborValue {
    fn from(drm: DeviceRetrievalMethod) -> Self {
        let transport_type = drm.transport_type().into();
        let version = drm.version().into();
        let retrieval_method = match drm {
            DeviceRetrievalMethod::NFC(opts) => opts.into(),
            DeviceRetrievalMethod::BLE(opts) => opts.into(),
            DeviceRetrievalMethod::WIFI(opts) => opts.into(),
        };
        CborValue::Array(vec![transport_type, version, retrieval_method])
    }
}

impl TryFrom<CborValue> for BleOptions {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<Self, Error> {
        if let CborValue::Map(mut map) = v {
            let central_client_mode = match (
                map.remove(&CborValue::Integer(1)),
                map.remove(&CborValue::Integer(11)),
            ) {
                (Some(CborValue::Bool(true)), Some(CborValue::Bytes(uuid))) => {
                    let uuid_bytes: [u8; 16] = uuid.try_into().map_err(|_| Error::Malformed)?;
                    Some(CentralClientMode {
                        uuid: Uuid::from_bytes(uuid_bytes),
                    })
                }
                (Some(CborValue::Bool(false)), _) => None,
                _ => return Err(Error::Malformed),
            };

            let peripheral_server_mode = match (
                map.remove(&CborValue::Integer(0)),
                map.remove(&CborValue::Integer(10)),
            ) {
                (Some(CborValue::Bool(true)), Some(CborValue::Bytes(uuid))) => {
                    let uuid_bytes: [u8; 16] = uuid.try_into().map_err(|_| Error::Malformed)?;
                    let ble_device_address = match map.remove(&CborValue::Integer(20)) {
                        Some(value) => Some(value.try_into().map_err(|_| Error::Malformed)?),
                        None => None,
                    };
                    Some(PeripheralServerMode {
                        uuid: Uuid::from_bytes(uuid_bytes),
                        ble_device_address,
                    })
                }
                (Some(CborValue::Bool(false)), _) => None,
                _ => return Err(Error::Malformed),
            };

            Ok(BleOptions {
                central_client_mode,
                peripheral_server_mode,
            })
        } else {
            Err(Error::Malformed)
        }
    }
}

impl From<BleOptions> for CborValue {
    fn from(o: BleOptions) -> CborValue {
        let mut map = BTreeMap::new();

        match o.central_client_mode {
            Some(CentralClientMode { uuid }) => {
                map.insert(CborValue::Integer(1), CborValue::Bool(true));
                map.insert(
                    CborValue::Integer(11),
                    CborValue::Bytes(uuid.as_bytes().to_vec()),
                );
            }
            None => {
                map.insert(CborValue::Integer(1), CborValue::Bool(false));
            }
        }

        match o.peripheral_server_mode {
            Some(PeripheralServerMode {
                uuid,
                ble_device_address,
            }) => {
                map.insert(CborValue::Integer(0), CborValue::Bool(true));
                map.insert(
                    CborValue::Integer(10),
                    CborValue::Bytes(uuid.as_bytes().to_vec()),
                );
                if let Some(address) = ble_device_address {
                    map.insert(CborValue::Integer(20), address.into());
                }
            }
            None => {
                map.insert(CborValue::Integer(0), CborValue::Bool(false));
            }
        }

        CborValue::Map(map)
    }
}

impl TryFrom<CborValue> for WifiOptions {
    type Error = Error;

    fn try_from(_v: CborValue) -> Result<Self, Error> {
        todo!()
    }
}

impl From<WifiOptions> for CborValue {
    fn from(o: WifiOptions) -> CborValue {
        let mut map = BTreeMap::<CborValue, CborValue>::new();
        if let Some(v) = o.pass_phrase {
            map.insert(CborValue::Integer(0), v.into());
        }
        if let Some(v) = o.channel_info_operating_class {
            map.insert(CborValue::Integer(1), v.into());
        }
        if let Some(v) = o.channel_info_channel_number {
            map.insert(CborValue::Integer(2), v.into());
        }
        if let Some(v) = o.band_info {
            map.insert(CborValue::Integer(3), v.into());
        }

        CborValue::Map(map)
    }
}

impl TryFrom<CborValue> for NfcOptions {
    type Error = Error;

    fn try_from(_v: CborValue) -> Result<Self, Error> {
        todo!()
    }
}

impl From<NfcOptions> for CborValue {
    fn from(o: NfcOptions) -> CborValue {
        let mut map = BTreeMap::<CborValue, CborValue>::new();
        map.insert(
            CborValue::Integer(0),
            CborValue::Integer(o.max_len_command_data_field.into()),
        );
        map.insert(
            CborValue::Integer(1),
            CborValue::Integer(o.max_len_response_data_field.into()),
        );

        CborValue::Map(map)
    }
}

impl From<ServerRetrievalMethods> for CborValue {
    fn from(m: ServerRetrievalMethods) -> CborValue {
        let mut map = BTreeMap::<CborValue, CborValue>::new();

        if let Some((x, y, z)) = m.web_api {
            map.insert(
                "webApi".to_string().into(),
                CborValue::Array(vec![x.into(), y.into(), z.into()]),
            );
        }

        if let Some((x, y, z)) = m.oidc {
            map.insert(
                "oidc".to_string().into(),
                CborValue::Array(vec![x.into(), y.into(), z.into()]),
            );
        }

        CborValue::Map(map)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::definitions::session::create_p256_ephemeral_keys;
    use uuid::Uuid;

    #[test]
    fn device_engagement_cbor_roundtrip() {
        let key_pair = create_p256_ephemeral_keys(0).unwrap();
        let public_key = Tag24::new(key_pair.1).unwrap();

        let uuid = Uuid::now_v1(&[0, 1, 2, 3, 4, 5]);

        let ble_option = BleOptions {
            peripheral_server_mode: None,
            central_client_mode: Some(CentralClientMode { uuid }),
        };

        let device_retrieval_methods =
            Some(NonEmptyVec::new(DeviceRetrievalMethod::BLE(ble_option)));

        let device_engagement = DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, public_key),
            device_retrieval_methods,
            server_retrieval_methods: None,
            protocol_info: None,
        };

        let bytes = serde_cbor::to_vec(&device_engagement).unwrap();
        let roundtripped = serde_cbor::from_slice(&bytes).unwrap();

        assert_eq!(device_engagement, roundtripped)
    }
}
