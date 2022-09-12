use crate::mdoc::bytestr::ByteStr;
use serde_cbor::Value as CborValue;
pub type EDeviceKeyBytes = Vec<u8>;
pub type EReaderKeyBytes = Vec<u8>;

pub type Security = (u64, EDeviceKeyBytes);
pub type DeviceRetrievalMethods = Vec<DeviceRetrievalMethod>;
pub type DeviceRetrievalMethod = (u64, u64, RetrievalOptions);
pub type ProtocolInfo = CborValue;
pub type Oidc = (u64, String, String);
pub type WebApi = (u64, String, String);

pub struct DeviceEngagement {
    version: String,
    security: Security,
    device_retrieval_methods: Option<DeviceRetrievalMethods>,
    server_retrieval_methods: Option<ServerRetrievalMethods>,
    protocol_info: Option<ProtocolInfo>,
}

pub enum RetrievalOptions {
    WIFIOPTIONS,
    BLEOPTIONS,
    NFCOPTIONS,
}

pub struct ServerRetrievalMethods {
    web_api: Option<WebApi>,
    oidc: Option<Oidc>,
}

pub struct BleOptions {
    peripheral_server_mode: bool,
    central_client_mode: bool,
    pheripheral_server_uuid: Option<ByteStr>,
    client_central_uuid: Option<ByteStr>,
    mdoc_ble_device_address_peripheral_server: Option<ByteStr>,
}
pub struct WifiOptions {
    pass_phrase: String,
    channel_info_operating_class: u64,
    channel_info_channel_number: u64,
    band_info: ByteStr,
}
pub struct NfcOptions {
    max_len_command_data_field: u64,
    max_len_response_data_field: u64,
}
