//! This module contains the definitions for the [DeviceEngagement] struct and related types.
//!
//! The [DeviceEngagement] struct represents a device engagement object, which contains information about a device's engagement with a server.  
//! It includes fields such as the `version`, `security details, `device retrieval methods, `server retrieval methods, and `protocol information.
//!
//! The module also provides implementations for conversions between [DeviceEngagement] and [CborValue], as well as other utility functions.

use std::{collections::BTreeMap, vec};

use anyhow::Result;
use ciborium::Value;
use coset::AsCborValue;
use isomdl_macros::{CborSerializableFromCborValue, FieldsNames};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use error::Error;
pub use nfc_options::NfcOptions;

use crate::cbor::CborValue;
use crate::definitions::helpers::Tag24;
use crate::definitions::helpers::{ByteStr, NonEmptyVec};
use crate::definitions::CoseKey;

pub mod error;
pub mod nfc_options;
pub type EDeviceKeyBytes = Tag24<CoseKey>;
pub type EReaderKeyBytes = Tag24<CoseKey>;

pub type DeviceRetrievalMethods = NonEmptyVec<DeviceRetrievalMethod>;
pub type ProtocolInfo = CborValue;
pub type Oidc = (u64, String, String);
pub type WebApi = (u64, String, String);

/// Represents a device engagement.
#[derive(Clone, Debug, CborSerializableFromCborValue, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue", rename_all = "camelCase")]
pub struct DeviceEngagement {
    /// The version of the device engagement.
    pub version: String,

    /// The security settings for the device engagement.
    pub security: Security,

    /// The optional device retrieval methods for the device engagement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_retrieval_methods: Option<DeviceRetrievalMethods>,

    /// The optional server retrieval methods for the device engagement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_retrieval_methods: Option<ServerRetrievalMethods>,

    /// The optional protocol information for the device engagement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_info: Option<ProtocolInfo>,
}

#[derive(Clone, Debug, CborSerializableFromCborValue, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(
    Clone, Debug, CborSerializableFromCborValue, FieldsNames, Serialize, Deserialize, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase")]
#[isomdl(rename_all = "camelCase")]
pub struct ServerRetrievalMethods {
    /// The `web API retrieval method. This field is optional and will be skipped during serialization if it is [None].
    #[serde(skip_serializing_if = "Option::is_none")]
    #[isomdl(skip_serializing_if = "Option::is_none")]
    web_api: Option<WebApi>,

    /// The `OIDC`` retrieval method. This field is optional and will be skipped during serialization if it is [None].
    #[serde(skip_serializing_if = "Option::is_none")]
    #[isomdl(skip_serializing_if = "Option::is_none")]
    oidc: Option<Oidc>,
}

/// Represents the options for `Bluetooth Low Energy` (BLE) device engagement.
#[derive(Clone, Debug, CborSerializableFromCborValue, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(
    Clone, Debug, CborSerializableFromCborValue, Serialize, Deserialize, PartialEq, Eq, Default,
)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub struct WifiOptions {
    /// The passphrase for the `WiFi connection. If [None], no passphrase is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pass_phrase: Option<String>,

    /// The operating class of the `WiFi` channel. If [None], the operating class is not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_info_operating_class: Option<u64>,

    /// The channel number of the `WiFi` channel. If [None], the channel number is not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_info_channel_number: Option<u64>,

    /// The band information of the `WiFi channel. If [None], the band information is not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    band_info: Option<ByteStr>,
}

impl coset::CborSerializable for Security {}
impl AsCborValue for Security {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut arr = value.into_array().map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "missing elements".to_string(),
            ))
        })?;
        if arr.len() != 2 {
            return Err(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "wrong number of items".to_string()),
            ));
        }
        Ok(Security(
            arr.remove(0)
                .into_integer()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "invalid integer".to_string(),
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "invalid integer".to_string(),
                    ))
                })?,
            EDeviceKeyBytes::new(CoseKey::from_cbor_value(arr.remove(0)).map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "invalid bytes".to_string(),
                ))
            })?)
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "missing elements".to_string(),
                ))
            })?,
        ))
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Array(vec![
            Value::Integer(self.0.into()),
            Value::Bytes(self.1.inner_bytes),
        ]))
    }
}

impl From<DeviceEngagement> for CborValue {
    fn from(device_engagement: DeviceEngagement) -> CborValue {
        let mut map = vec![];
        map.push((
            Value::Integer(0.into()),
            Value::Text(device_engagement.version),
        ));
        let v = device_engagement
            .security
            .1
            .to_cbor_value()
            .map_err(|_| Error::Malformed)
            .unwrap();
        map.push((
            Value::Integer(1.into()),
            Value::Array(vec![Value::Integer(device_engagement.security.0.into()), v]),
        ));
        if let Some(methods) = device_engagement.device_retrieval_methods {
            let methods = Vec::from(methods)
                .into_iter()
                .flat_map(|v| match v {
                    DeviceRetrievalMethod::WIFI(v) => v.to_cbor_value(),
                    DeviceRetrievalMethod::BLE(v) => v.to_cbor_value(),
                    DeviceRetrievalMethod::NFC(v) => v.to_cbor_value(),
                })
                .collect();
            map.push((Value::Integer(2.into()), Value::Array(methods)));
        }
        if let Some(methods) = device_engagement.server_retrieval_methods {
            map.push((Value::Integer(3.into()), methods.to_cbor_value().unwrap()));
        }
        if let Some(_info) = device_engagement.protocol_info {
            // Usage of protocolinfo is RFU and should for now be none
        }

        Value::Map(map).into()
    }
}

impl TryFrom<CborValue> for DeviceEngagement {
    type Error = Error;
    fn try_from(v: CborValue) -> Result<Self, Error> {
        if let Value::Map(map) = v.into() {
            let mut map = map
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect::<BTreeMap<CborValue, CborValue>>();
            let device_engagement_version = map.remove(&Value::Integer(0.into()).into());
            if let Some(Value::Text(v)) = device_engagement_version.map(ciborium::Value::from) {
                if v != "1.0" {
                    return Err(Error::UnsupportedVersion);
                }
            } else {
                return Err(Error::Malformed);
            }
            let device_engagement_security = Security::from_cbor_value(
                map.remove(&Value::Integer(1.into()).into())
                    .ok_or(Error::Malformed)
                    .map(|v| v.into())?,
            )
            .map_err(|_| Error::Malformed)?;
            let security = Security::from_cbor_value(
                device_engagement_security
                    .to_cbor_value()
                    .map_err(|_| Error::Malformed)?,
            )
            .map_err(|_| Error::Malformed)?;

            let device_retrieval_methods = map
                .remove(&Value::Integer(2.into()).into())
                .map(|v| v.into())
                .map(DeviceRetrievalMethods::from_cbor_value)
                .transpose()
                .map_err(|_| Error::Malformed)?;

            let server_retrieval_methods = map
                .remove(&Value::Integer(3.into()).into())
                .map(|v| v.into())
                .map(ServerRetrievalMethods::from_cbor_value)
                .transpose()
                .map_err(|_| Error::Malformed)?;
            if server_retrieval_methods.is_some() {
                //tracing::warn!("server_retrieval is unimplemented.")
            }
            let protocol_info = map.remove(&Value::Integer(4.into()).into());
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

    pub fn to_qr_code_uri(&self) -> Result<String, coset::CoseError> {
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
        if let Value::Array(list) = value.into() {
            let method: [Value; 3] = list
                .into_iter()
                .collect::<Vec<Value>>()
                .try_into()
                .map_err(|_| Error::Malformed)?;
            match method {
                [Value::Integer(i1), Value::Integer(i11), methods]
                    if <ciborium::value::Integer as Into<i128>>::into(i1) == 1_i128
                        && <ciborium::value::Integer as Into<i128>>::into(i11) == 1_i128 =>
                {
                    let nfc_options: CborValue = methods.into();
                    let nfc_options = NfcOptions::try_from(nfc_options)?;
                    Ok(DeviceRetrievalMethod::NFC(nfc_options))
                }
                [Value::Integer(i2), Value::Integer(i1), ble_options]
                    if <ciborium::value::Integer as Into<i128>>::into(i1) == 1_i128
                        && <ciborium::value::Integer as Into<i128>>::into(i2) == 2_i128 =>
                {
                    let ble_options: CborValue = ble_options.into();
                    let ble_options = BleOptions::try_from(ble_options)?;
                    Ok(DeviceRetrievalMethod::BLE(ble_options))
                }
                [Value::Integer(i3), Value::Integer(i1), wifi_options]
                    if <ciborium::value::Integer as Into<i128>>::into(i1) == 1_i128
                        && <ciborium::value::Integer as Into<i128>>::into(i3) == 3_i128 =>
                {
                    let wifi_options: CborValue = wifi_options.into();
                    let wifi_options = WifiOptions::try_from(wifi_options)?;
                    Ok(DeviceRetrievalMethod::WIFI(wifi_options))
                }
                [Value::Integer(_), _, _] => Err(Error::UnsupportedDRM),
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
            DeviceRetrievalMethod::NFC(opts) => opts.to_cbor_value().unwrap(),
            DeviceRetrievalMethod::BLE(opts) => opts.to_cbor_value().unwrap(),
            DeviceRetrievalMethod::WIFI(opts) => opts.to_cbor_value().unwrap(),
        };
        Value::Array(vec![transport_type, version, retrieval_method]).into()
    }
}

impl TryFrom<CborValue> for BleOptions {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<Self, Error> {
        let v: Value = v.into();
        if let Value::Map(map) = v {
            let mut map = map
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect::<BTreeMap<CborValue, CborValue>>();
            let central_client_mode = match (
                map.remove(&Value::Integer(1.into()).into())
                    .map(|v| v.into()),
                map.remove(&Value::Integer(11.into()).into())
                    .map(|v| v.into()),
            ) {
                (Some(Value::Bool(true)), Some(Value::Bytes(uuid))) => {
                    let uuid_bytes: [u8; 16] = uuid.try_into().map_err(|_| Error::Malformed)?;
                    Some(CentralClientMode {
                        uuid: Uuid::from_bytes(uuid_bytes),
                    })
                }
                (Some(Value::Bool(false)), _) => None,
                _ => return Err(Error::Malformed),
            };

            let peripheral_server_mode = match (
                map.remove(&Value::Integer(0.into()).into())
                    .map(|v| v.into()),
                map.remove(&Value::Integer(10.into()).into())
                    .map(|v| v.into()),
            ) {
                (Some(Value::Bool(true)), Some(Value::Bytes(uuid))) => {
                    let uuid_bytes: [u8; 16] = uuid.try_into().map_err(|_| Error::Malformed)?;
                    let ble_device_address: Option<ByteStr> =
                        match map.remove(&Value::Integer(20.into()).into()) {
                            Some(value) => Some(value.try_into().map_err(|_| Error::Malformed)?),
                            None => None,
                        };
                    Some(PeripheralServerMode {
                        uuid: Uuid::from_bytes(uuid_bytes),
                        ble_device_address,
                    })
                }
                (Some(Value::Bool(false)), _) => None,
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
        let mut map: BTreeMap<CborValue, CborValue> = BTreeMap::new();

        match o.central_client_mode {
            Some(CentralClientMode { uuid }) => {
                map.insert(Value::Integer(1.into()).into(), Value::Bool(true).into());
                map.insert(
                    Value::Integer(11.into()).into(),
                    Value::Bytes(uuid.as_bytes().to_vec()).into(),
                );
            }
            None => {
                map.insert(Value::Integer(1.into()).into(), Value::Bool(false).into());
            }
        }

        match o.peripheral_server_mode {
            Some(PeripheralServerMode {
                uuid,
                ble_device_address,
            }) => {
                map.insert(Value::Integer(0.into()).into(), Value::Bool(true).into());
                map.insert(
                    Value::Integer(10.into()).into(),
                    Value::Bytes(uuid.as_bytes().to_vec()).into(),
                );
                if let Some(address) = ble_device_address {
                    map.insert(Value::Integer(20.into()).into(), address.into());
                }
            }
            None => {
                map.insert(Value::Integer(0.into()).into(), Value::Bool(false).into());
            }
        }

        Value::Map(map.into_iter().map(|(k, v)| (k.into(), v.into())).collect()).into()
    }
}

impl TryFrom<CborValue> for WifiOptions {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<Self, Error> {
        fn lookup_opt_string(
            map: &BTreeMap<CborValue, CborValue>,
            idx: i128,
        ) -> Result<Option<String>, Error> {
            match map
                .get(&Value::Integer(idx.try_into().map_err(|_| Error::InvalidWifiOptions)?).into())
            {
                None => Ok(None),
                Some(CborValue::Text(text)) => Ok(Some(text.to_string())),
                _ => Err(Error::InvalidWifiOptions),
            }
        }

        fn lookup_opt_u64(
            map: &BTreeMap<CborValue, CborValue>,
            idx: i128,
        ) -> Result<Option<u64>, Error> {
            match map
                .get(&Value::Integer(idx.try_into().map_err(|_| Error::InvalidWifiOptions)?).into())
            {
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
            match map
                .get(&Value::Integer(idx.try_into().map_err(|_| Error::InvalidWifiOptions)?).into())
            {
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
            map.insert(Value::Integer(0.into()).into(), v.into());
        }
        if let Some(v) = o.channel_info_operating_class {
            map.insert(Value::Integer(1.into()).into(), v.into());
        }
        if let Some(v) = o.channel_info_channel_number {
            map.insert(Value::Integer(2.into()).into(), v.into());
        }
        if let Some(v) = o.band_info {
            map.insert(Value::Integer(3.into()).into(), v.into());
        }

        Value::Map(map.into_iter().map(|(k, v)| (k.into(), v.into())).collect()).into()
    }
}

impl From<ServerRetrievalMethods> for CborValue {
    fn from(m: ServerRetrievalMethods) -> CborValue {
        let mut map = vec![];

        if let Some((x, y, z)) = m.web_api {
            map.push((
                Value::Text("webApi".to_string()),
                Value::Array(vec![x.into(), y.into(), z.into()]),
            ));
        }

        if let Some((x, y, z)) = m.oidc {
            map.push((
                Value::Text("oidc".to_string()),
                Value::Array(vec![x.into(), y.into(), z.into()]),
            ));
        }

        Value::Map(map).into()
    }
}

impl TryFrom<CborValue> for ServerRetrievalMethods {
    type Error = Error;

    fn try_from(value: CborValue) -> std::result::Result<Self, Self::Error> {
        let mut map = value.into_map().map_err(|_| Error::Malformed)?;
        let mut web_api = map
            .remove(&ServerRetrievalMethods::fn_web_api().into())
            .map(|v| v.into_array())
            .transpose()
            .map_err(|_| Error::Malformed)?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut oidc = map
            .remove(&ServerRetrievalMethods::fn_oidc().into())
            .map(|v| v.into_array())
            .transpose()
            .map_err(|_| Error::Malformed)?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        Ok(ServerRetrievalMethods {
            web_api: Some((
                web_api.remove(0).try_into().map_err(|_| Error::Malformed)?,
                web_api.remove(0).try_into().map_err(|_| Error::Malformed)?,
                web_api.remove(0).try_into().map_err(|_| Error::Malformed)?,
            )),
            oidc: Some((
                oidc.remove(0).try_into().map_err(|_| Error::Malformed)?,
                oidc.remove(0).try_into().map_err(|_| Error::Malformed)?,
                oidc.remove(0).try_into().map_err(|_| Error::Malformed)?,
            )),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::definitions::session::create_p256_ephemeral_keys;
    use coset::CborSerializable;
    use uuid::Uuid;

    use super::*;

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

        let bytes = device_engagement.clone().to_vec().unwrap();
        let roundtripped = DeviceEngagement::from_slice(&bytes).unwrap();

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
        let bytes: Vec<u8> = wifi_options.clone().to_vec().unwrap();
        let deserialized = WifiOptions::from_slice(&bytes).unwrap();
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
