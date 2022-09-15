use crate::definitions::helpers::ByteStr;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;

pub type EDeviceKeyBytes = Vec<u8>;
pub type EReaderKeyBytes = Vec<u8>;
//the u64 represents a cipher suite identifier
pub type Security = (u64, EDeviceKeyBytes);
pub type DeviceRetrievalMethods = Vec<DeviceRetrievalMethod>;
// the first u64 represents a type, the second a version
pub type DeviceRetrievalMethod = (u64, u64, RetrievalOptions);
pub type ProtocolInfo = CborValue;
pub type Oidc = (u64, String, String);
pub type WebApi = (u64, String, String);

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    web_api: Option<WebApi>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oidc: Option<Oidc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BleOptions {
    pub peripheral_server_mode: bool,
    pub central_client_mode: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peripheral_server_uuid: Option<ByteStr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_central_uuid: Option<ByteStr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
