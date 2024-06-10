use crate::definitions::device_key::cose_key::Error as CoseKeyError;
use crate::definitions::helpers::tag24::Error as Tag24Error;
use serde_cbor::Error as SerdeCborError;

/// Errors that can occur when deserialising a DeviceEngagement.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Expected isomdl major version 1")]
    UnsupportedVersion,
    #[error("Unsupported device retrieval method")]
    UnsupportedDRM,
    #[error("Unimplemented BLE option")]
    Unimplemented,
    #[error("Invalid DeviceEngagment found")]
    InvalidDeviceEngagement,
    #[error("Invalid WifiOptions found")]
    InvalidWifiOptions,
    #[error("Invalid NfcOptions found")]
    InvalidNfcOptions,
    #[error("Malformed object not recognised")]
    Malformed,
    #[error("Something went wrong parsing a cose key")]
    CoseKeyError,
    #[error("Something went wrong parsing a tag24")]
    Tag24Error,
    #[error("Could not deserialize from cbor")]
    SerdeCborError,
    #[error("NFC Command Data Length must be between 255 and 65535")]
    InvalidNfcCommandDataLengthError,
    #[error("NFC Response Data Length must be between 256 and 65536")]
    InvalidNfcResponseDataLengthError,
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
