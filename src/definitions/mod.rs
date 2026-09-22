//! This module contains the definitions for all components involved in the lib.
pub mod app_attestation;
pub mod device_engagement;
pub mod device_key;
pub mod device_request;
pub mod device_response;
pub mod device_signed;
pub mod helpers;
pub mod issuer_signed;
pub mod issuer_signed_dehydrated;
pub mod mcd;
pub mod mso;
pub mod namespaces;
pub mod session;
pub mod traits;
pub mod validity_info;
pub mod x509;

pub use device_engagement::{
    BleOptions, DeviceEngagement, DeviceRetrievalMethod, NfcOptions, Security, WifiOptions,
};
pub use device_key::cose_key::{EC2Curve, Error, EC2Y};
pub use device_key::{CoseKey, DeviceKeyInfo, KeyAuthorizations};
pub use device_request::DocRequest;

/// The ISO/IEC 18013-5 mobile driving licence doc type.
pub const MDL_DOC_TYPE: &str = "org.iso.18013.5.1.mDL";

/// The EUDI Person Identification Data doc type, which is also its namespace.
pub const EUDI_PID_DOC_TYPE: &str = "eu.europa.ec.eudi.pid.1";

pub use device_response::{DeviceResponse, Document};
pub use device_signed::{DeviceAuth, DeviceSigned};
pub use issuer_signed::{IssuerSigned, IssuerSignedItem};
pub use mso::{DigestAlgorithm, DigestId, DigestIds, Mso};
pub use session::{SessionData, SessionEstablishment, SessionTranscript180135};
pub use validity_info::ValidityInfo;
