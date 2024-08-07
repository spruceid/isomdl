//! This module contains the definitions for the [DeviceEngagement] struct and related types.
//!
//! The [DeviceEngagement] struct represents a device engagement object, which contains information about a device's engagement with a server.  
//! It includes fields such as the `version`, `security details, `device retrieval methods, `server retrieval methods, and `protocol information.
//!
//! The module also provides implementations for conversions between [DeviceEngagement] and [CborValue], as well as other utility functions.
use crate::definitions::helpers::Tag24;
use crate::definitions::helpers::{ByteStr, NonEmptyVec};
use crate::definitions::CoseKey;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::{collections::BTreeMap, vec};
use uuid::Uuid;

pub mod error;
pub use error::Error;

pub mod nfc_options;
pub use nfc_options::NfcOptions;

pub type EDeviceKeyBytes = Tag24<CoseKey>;
pub type EReaderKeyBytes = Tag24<CoseKey>;

pub type DeviceRetrievalMethods = NonEmptyVec<DeviceRetrievalMethod>;
pub type ProtocolInfo = CborValue;
pub type Oidc = (u64, String, String);
pub type WebApi = (u64, String, String);

/// Represents a device engagement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue", rename_all = "camelCase")]
pub struct DeviceEngagement {
    /// The version of the device engagement.
    pub version: String,

    /// The security settings for the device engagement.
    pub security: Security,

    /// The optional device retrieval methods for the device engagement.
    pub device_retrieval_methods: Option<DeviceRetrievalMethods>,

    /// The optional server retrieval methods for the device engagement.
    pub server_retrieval_methods: Option<ServerRetrievalMethods>,

    /// The optional protocol information for the device engagement.
    pub protocol_info: Option<ProtocolInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub enum DeviceRetrievalMethod {
    /// Represents the options for a WiFi connection.
    WIFI(WifiOptions),

    /// Represents the BLE options for device engagement.
    ///
    /// This struct is used to configure the BLE options for device engagement.  
    /// It contains the necessary parameters and settings for BLE communication.
    BLE(BleOptions),

    /// Represents the options for NFC engagement.
    NFC(NfcOptions),
}

/// Represents the bytes of an EDevice key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Security(pub u64, pub EDeviceKeyBytes);

/// Represents the server retrieval methods for device engagement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerRetrievalMethods {
    /// The `web API retrieval method. This field is optional and will be skipped during serialization if it is [None].
    web_api: Option<WebApi>,

    /// The `OIDC`` retrieval method. This field is optional and will be skipped during serialization if it is [None].
    oidc: Option<Oidc>,
}

/// Represents the options for `Bluetooth Low Energy` (BLE) device engagement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub struct BleOptions {
    /// The peripheral server mode for `BLE` device engagement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peripheral_server_mode: Option<PeripheralServerMode>,

    /// The central client mode for `BLE` device engagement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub central_client_mode: Option<CentralClientMode>,
}

/// Represents a peripheral server mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeripheralServerMode {
    /// The 'UUID' of the peripheral server.
    pub uuid: Uuid,

    /// The 'BLE' device address of the peripheral server, if available.
    pub ble_device_address: Option<ByteStr>,
}

/// Represents the central client mode for device engagement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CentralClientMode {
    pub uuid: Uuid,
}

/// Represents the options for a `WiFi` device engagement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub struct WifiOptions {
    /// The passphrase for the `WiFi connection. If [None], no passphrase is required.
    pass_phrase: Option<String>,

    /// The operating class of the `WiFi` channel. If [None], the operating class is not specified.
    channel_info_operating_class: Option<u64>,

    /// The channel number of the `WiFi` channel. If [None], the channel number is not specified.
    channel_info_channel_number: Option<u64>,

    /// The band information of the `WiFi channel. If [None], the band information is not specified.
    band_info: Option<ByteStr>,
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
                //tracing::warn!("server_retrieval is unimplemented.")
            }
            let protocol_info = map.remove(&CborValue::Integer(4));
            if protocol_info.is_some() {
                //tracing::warn!("protocol_info is RFU and has been ignored in deserialization.")
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

impl Tag24<DeviceEngagement> {
    const BASE64_CONFIG: base64::Config = base64::Config::new(base64::CharacterSet::UrlSafe, false);

    pub fn to_qr_code_uri(&self) -> Result<String, serde_cbor::Error> {
        let mut qr_code_uri = String::from("mdoc:");
        base64::encode_config_buf(&self.inner_bytes, Self::BASE64_CONFIG, &mut qr_code_uri);
        Ok(qr_code_uri)
    }

    pub fn from_qr_code_uri(qr_code_uri: &str) -> anyhow::Result<Self> {
        let encoded_de = qr_code_uri
            .strip_prefix("mdoc:")
            .ok_or_else(|| anyhow::anyhow!("qr code has invalid prefix"))?;
        let decoded_de = base64::decode_config(encoded_de, Self::BASE64_CONFIG)?;
        Tag24::<DeviceEngagement>::from_bytes(decoded_de).map_err(Into::into)
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

    fn try_from(v: CborValue) -> Result<Self, Error> {
        fn lookup_opt_string(
            map: &BTreeMap<CborValue, CborValue>,
            idx: i128,
        ) -> Result<Option<String>, Error> {
            match map.get(&CborValue::Integer(idx)) {
                None => Ok(None),
                Some(CborValue::Text(text)) => Ok(Some(text.to_string())),
                _ => Err(Error::InvalidWifiOptions),
            }
        }

        fn lookup_opt_u64(
            map: &BTreeMap<CborValue, CborValue>,
            idx: i128,
        ) -> Result<Option<u64>, Error> {
            match map.get(&CborValue::Integer(idx)) {
                None => Ok(None),
                Some(CborValue::Integer(int_val)) => {
                    let uint_val =
                        u64::try_from(*int_val).map_err(|_| Error::InvalidWifiOptions)?;
                    Ok(Some(uint_val))
                }
                _ => Err(Error::InvalidWifiOptions),
            }
        }

        fn lookup_opt_bytestr(
            map: &BTreeMap<CborValue, CborValue>,
            idx: i128,
        ) -> Result<Option<ByteStr>, Error> {
            match map.get(&CborValue::Integer(idx)) {
                None => Ok(None),
                Some(cbor_val) => {
                    let byte_str = ByteStr::try_from(cbor_val.clone())
                        .map_err(|_| Error::InvalidWifiOptions)?;
                    Ok(Some(byte_str))
                }
            }
        }

        let map: BTreeMap<CborValue, CborValue> = match v {
            CborValue::Map(map) => Ok(map),
            _ => Err(Error::InvalidWifiOptions),
        }?;

        Ok(WifiOptions::default())
            .and_then(|wifi_opts| {
                let pass_phrase = lookup_opt_string(&map, 0)?;
                Ok(WifiOptions {
                    pass_phrase,
                    ..wifi_opts
                })
            })
            .and_then(|wifi_opts| {
                let channel_info_operating_class = lookup_opt_u64(&map, 1)?;
                Ok(WifiOptions {
                    channel_info_operating_class,
                    ..wifi_opts
                })
            })
            .and_then(|wifi_opts| {
                let channel_info_channel_number = lookup_opt_u64(&map, 2)?;
                Ok(WifiOptions {
                    channel_info_channel_number,
                    ..wifi_opts
                })
            })
            .and_then(|wifi_opts| {
                let band_info = lookup_opt_bytestr(&map, 3)?;
                Ok(WifiOptions {
                    band_info,
                    ..wifi_opts
                })
            })
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
        let key_pair = create_p256_ephemeral_keys().unwrap();
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

    #[test]
    fn device_engagement_qr_code_roundtrip() {
        const EXAMPLE_QR_CODE: &str = "mdoc:owBjMS4wAYIB2BhYS6QBAiABIVgglyWXuAyJ6iRNc8OlYXenvkJt23rJPdtIhlawXqr-yf0iWCC1GQSH8tIwTYVwha_ZoPL20_saYXrGIbrCm133H0ki-QKBgwIBowD1AfQKUH2RiuAEbUVzrsrOiUnSPDw";
        let de = Tag24::<DeviceEngagement>::from_qr_code_uri(EXAMPLE_QR_CODE).unwrap();
        let roundtripped = de.to_qr_code_uri().unwrap();
        assert_eq!(EXAMPLE_QR_CODE, roundtripped);
    }

    fn wifi_options_cbor_roundtrip_test(wifi_options: WifiOptions) {
        let bytes: Vec<u8> = serde_cbor::to_vec(&wifi_options).unwrap();
        let deserialized: WifiOptions = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(wifi_options, deserialized);
    }

    #[test]
    fn wifi_options_cbor_roundtrip_all_some() {
        let wifi_options: WifiOptions = WifiOptions {
            pass_phrase: Some(String::from("secret")),
            channel_info_operating_class: Some(2),
            channel_info_channel_number: Some(3),
            band_info: Some(ByteStr::from(vec![20, 30, 40])),
        };

        wifi_options_cbor_roundtrip_test(wifi_options);
    }

    #[test]
    fn wifi_options_cbor_roundtrip_all_none() {
        let wifi_options: WifiOptions = WifiOptions {
            pass_phrase: None,
            channel_info_operating_class: None,
            channel_info_channel_number: None,
            band_info: None,
        };

        wifi_options_cbor_roundtrip_test(wifi_options);
    }

    #[test]
    fn wifi_options_cbor_roundtrip_even_some() {
        let wifi_options: WifiOptions = WifiOptions {
            pass_phrase: Some(String::from("secret number 2 with spaces and $#$@$!")),
            channel_info_operating_class: None,
            channel_info_channel_number: Some(123),
            band_info: None,
        };

        wifi_options_cbor_roundtrip_test(wifi_options);
    }

    #[test]
    fn wifi_options_cbor_roundtrip_odd_some() {
        let wifi_options: WifiOptions = WifiOptions {
            pass_phrase: None,
            channel_info_operating_class: Some(5432),
            channel_info_channel_number: None,
            band_info: Some(ByteStr::from(vec![99, 33, 22, 66, 88, 22, 125, 76])),
        };

        wifi_options_cbor_roundtrip_test(wifi_options);
    }
}
