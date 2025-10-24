use ciborium::de::Error;
pub use coset::{
    iana::{self, EnumI64},
    AsCborValue, TaggedCborSerializable,
};
use serde::{Deserialize, Serialize};

use crate::definitions::helpers::{ByteStr, Tag24};
use crate::definitions::CoseKey;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileIdCapabilityDescriptor {
    // spec: uint
    pub version: u64,

    // Accept both a keyed-map form and a flat array form for the app descriptor.
    #[serde(rename = "mobileIdApplicationDescriptor")]
    pub mobile_id_application_descriptor: MobileIdApplicationDescriptor,

    #[serde(default)]
    pub secure_area_attestation_objects: Vec<SecureAreaAttestationObject>,
}

impl TaggedCborSerializable for MobileIdCapabilityDescriptor {
    const TAG: u64 = 24;
}

impl AsCborValue for MobileIdCapabilityDescriptor {
    fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
        let bytes = match value {
            ciborium::Value::Bytes(b) => b,
            _ => {
                return Err(coset::CoseError::DecodeFailed(Error::Semantic(
                    None,
                    "Invalid CBOR value".into(),
                )))
            }
        };

        ciborium::from_reader(&bytes[..])
            .map_err(|e| coset::CoseError::DecodeFailed(Error::Semantic(None, e.to_string())))
    }

    fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&self, &mut bytes)?;

        Ok(ciborium::Value::Bytes(bytes))
    }
}

impl TaggedCborSerializable for MobileIdApplicationDescriptor {
    const TAG: u64 = 24;
}

impl AsCborValue for MobileIdApplicationDescriptor {
    fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
        let bytes = match value {
            ciborium::Value::Bytes(b) => b,
            _ => {
                return Err(coset::CoseError::DecodeFailed(Error::Semantic(
                    None,
                    "Invalid CBOR value".into(),
                )))
            }
        };

        ciborium::from_reader(&bytes[..])
            .map_err(|e| coset::CoseError::DecodeFailed(Error::Semantic(None, e.to_string())))
    }

    fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&self, &mut bytes)?;

        Ok(ciborium::Value::Bytes(bytes))
    }
}

/* ------------------------------
MobileIdApplicationDescriptor
------------------------------ */

/// Mobile ID Capaibility Descriptor
///
/// For more details see ISO-23220-3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileIdApplicationDescriptor {
    pub app_supported_dev_features: AppSupportedDevFeatures,
    pub app_engagement_interface: AppEngagementInterfaces,
    pub app_data_transmission_interface: AppDataTransmissionInterfaces,
    pub app_attestation_key_bytes: Option<AppAttestationKeyBytes>,
    pub certification: Certifications,
}

// Internal helper that can decode either a map (with "0".."4") or an array [0..4].
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum MobileIdApplicationDescriptorDe {
    MapForm {
        #[serde(rename = "0", default)]
        app_supported_dev_features: AppSupportedDevFeatures,
        #[serde(rename = "1", default)]
        app_engagement_interface: AppEngagementInterfaces,
        #[serde(rename = "2", default)]
        app_data_transmission_interface: AppDataTransmissionInterfaces,
        #[serde(rename = "3")]
        app_attestation_key_bytes: Option<AppAttestationKeyBytes>,
        #[serde(rename = "4", default)]
        certification: Certifications,
    },
    // Array form: [0]=features, [1]=engagement, [2]=transmission, [3]=attestKey, [4]=certs
    ArrayForm(
        #[serde(default)] AppSupportedDevFeatures,
        #[serde(default)] AppEngagementInterfaces,
        #[serde(default)] AppDataTransmissionInterfaces,
        Option<AppAttestationKeyBytes>,
        #[serde(default)] Certifications,
    ),
}

impl<'de> Deserialize<'de> for MobileIdApplicationDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match MobileIdApplicationDescriptorDe::deserialize(deserializer) {
            Ok(de_result) => match de_result {
                MobileIdApplicationDescriptorDe::MapForm {
                    app_supported_dev_features,
                    app_engagement_interface,
                    app_data_transmission_interface,
                    app_attestation_key_bytes,
                    certification,
                } => Ok(Self {
                    app_supported_dev_features,
                    app_engagement_interface,
                    app_data_transmission_interface,
                    app_attestation_key_bytes,
                    certification,
                }),
                MobileIdApplicationDescriptorDe::ArrayForm(
                    app_supported_dev_features,
                    app_engagement_interface,
                    app_data_transmission_interface,
                    app_attestation_key_bytes,
                    certification,
                ) => Ok(Self {
                    app_supported_dev_features,
                    app_engagement_interface,
                    app_data_transmission_interface,
                    app_attestation_key_bytes,
                    certification,
                }),
            },
            Err(err) => Err(err),
        }
    }
}

impl Serialize for MobileIdApplicationDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Prefer the canonical map form with "0".."4" keys
        #[derive(Serialize)]
        struct MapSer<'a> {
            #[serde(rename = "0", skip_serializing_if = "Vec::is_empty")]
            app_supported_dev_features: &'a AppSupportedDevFeatures,
            #[serde(rename = "1", skip_serializing_if = "Vec::is_empty")]
            app_engagement_interface: &'a AppEngagementInterfaces,
            #[serde(rename = "2", skip_serializing_if = "Vec::is_empty")]
            app_data_transmission_interface: &'a AppDataTransmissionInterfaces,
            #[serde(rename = "3", skip_serializing_if = "Option::is_none")]
            app_attestation_key_bytes: &'a Option<AppAttestationKeyBytes>,
            #[serde(rename = "4", skip_serializing_if = "Vec::is_empty")]
            certification: &'a Certifications,
        }
        MapSer {
            app_supported_dev_features: &self.app_supported_dev_features,
            app_engagement_interface: &self.app_engagement_interface,
            app_data_transmission_interface: &self.app_data_transmission_interface,
            app_attestation_key_bytes: &self.app_attestation_key_bytes,
            certification: &self.certification,
        }
        .serialize(serializer)
    }
}

/* ------------------------------
Numeric lists (support other -n)
------------------------------ */

pub type AppSupportedDevFeatures = Vec<i64>;
pub mod app_supported_dev_feature {
    pub const WEBVIEW_FEATURE: i64 = 0;
    pub const SIMPLE_VIEW_FEATURE: i64 = 1;
}

pub type AppEngagementInterfaces = Vec<i64>;
pub mod app_engagement_interface {
    pub const QR: i64 = 0;
    pub const NFC: i64 = 1;
}

pub type AppDataTransmissionInterfaces = Vec<i64>;
pub mod app_data_transmission_interface {
    pub const NFC: i64 = 0;
    pub const BLE: i64 = 1;
    pub const WIFI: i64 = 2;
    pub const INTERNET: i64 = 3;
}

/// The CBOR bytes-encoded MobileIdAttestationKey (bstr .cbor COSE_Key)
pub type AppAttestationKeyBytes = ByteStr; // Tag24<CoseKey>;

/* ------------------------------
Certifications (bstr // tstr)
------------------------------ */

pub type Certifications = Vec<CertificationItem>;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CertificationItem {
    Bytes(ByteStr),
    Text(String),
}

/* ------------------------------
SecureAreaAttestationObject
------------------------------ */

/// Secure Area Attestation Object
///
/// Defined in ISO-23220-3
#[derive(Debug, Clone)]
pub struct SecureAreaAttestationObject {
    pub sa_encoding: SaEncoding,
    pub sa_attestation_object_value: SaAttestationObjectValue,
}

// Accept either map {"saEncoding":..,"saAttestationObjectValue":..}
// or array [saEncoding, saAttestationObjectValue]
// Custom deserializer handles both map and array forms without untagged enum issues
impl<'de> Deserialize<'de> for SecureAreaAttestationObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, SeqAccess, Visitor};
        use std::fmt;

        struct SecureAreaAttestationObjectVisitor;

        impl<'de> Visitor<'de> for SecureAreaAttestationObjectVisitor {
            type Value = SecureAreaAttestationObject;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("SecureAreaAttestationObject as map or array")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut sa_encoding: Option<SaEncoding> = None;
                let mut sa_attestation_object_value: Option<SaAttestationObjectValue> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "saEncoding" => {
                            sa_encoding = Some(map.next_value()?);
                        }
                        "saAttestationObjectValue" => {
                            sa_attestation_object_value = Some(map.next_value()?);
                        }
                        _ => {
                            // Skip unknown fields
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let sa_encoding = sa_encoding.ok_or_else(|| Error::missing_field("saEncoding"))?;
                let sa_attestation_object_value = sa_attestation_object_value
                    .ok_or_else(|| Error::missing_field("saAttestationObjectValue"))?;

                Ok(SecureAreaAttestationObject {
                    sa_encoding,
                    sa_attestation_object_value,
                })
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let sa_encoding = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(0, &"at least 1 element"))?;
                let sa_attestation_object_value = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(1, &"at least 2 elements"))?;

                Ok(SecureAreaAttestationObject {
                    sa_encoding,
                    sa_attestation_object_value,
                })
            }
        }

        deserializer.deserialize_any(SecureAreaAttestationObjectVisitor)
    }
}

impl Serialize for SecureAreaAttestationObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct MapSer<'a> {
            #[serde(rename = "saEncoding")]
            sa_encoding: &'a SaEncoding,
            #[serde(rename = "saAttestationObjectValue")]
            sa_attestation_object_value: &'a SaAttestationObjectValue,
        }
        MapSer {
            sa_encoding: &self.sa_encoding,
            sa_attestation_object_value: &self.sa_attestation_object_value,
        }
        .serialize(serializer)
    }
}

// saEncoding as numeric
pub type SaEncoding = u8;
pub mod sa_encoding {
    pub const DEFAULT: u8 = 0;
    pub const SAAO_ANNEX_D: u8 = 1;
    pub const ISO7816_15: u8 = 2;
}

/* ------------------------------
SaAttestationObjectValue
------------------------------ */

/// Secure Area Attestation Object
#[derive(Debug, Clone)]
pub struct SaAttestationObjectValue {
    pub sa_index: u64,                                            // 0 (required)
    pub sa_type: Option<i64>,                                     // 1
    pub sa_supported_user_auth: Vec<i64>,                         // 2
    pub sa_crypto_suites: SecureAreaCryptoSuites,                 // 3
    pub sa_crypto_key_definition: SaCryptoKeyDefinitions,         // 4
    pub sa_interface: i64,                                        // 5 (required)
    pub sa_attestation_bytes: Option<SaAttestationKeyBytes>,      // 6
    pub sa_attestation_statement: Option<SaAttestationStatement>, // 7
    pub sa_attestation_format: Option<i64>,                       // 8
    pub certification: Certifications,                            // 9
}

impl<'de> Deserialize<'de> for SaAttestationObjectValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, SeqAccess, Visitor};
        use std::fmt;

        struct SaAttestationObjectValueVisitor;

        impl<'de> Visitor<'de> for SaAttestationObjectValueVisitor {
            type Value = SaAttestationObjectValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("SaAttestationObjectValue as map or array")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut sa_index: Option<u64> = None;
                let mut sa_type: Option<i64> = None;
                let mut sa_supported_user_auth: Vec<i64> = Vec::new();
                let mut sa_crypto_suites: SecureAreaCryptoSuites = Vec::new();
                let mut sa_crypto_key_definition: SaCryptoKeyDefinitions = Vec::new();
                let mut sa_interface: Option<i64> = None;
                let mut sa_attestation_bytes: Option<SaAttestationKeyBytes> = None;
                let mut sa_attestation_statement: Option<SaAttestationStatement> = None;
                let mut sa_attestation_format: Option<i64> = None;
                let mut certification: Certifications = Vec::new();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "0" => {
                            sa_index = Some(map.next_value()?);
                        }
                        "1" => {
                            sa_type = Some(map.next_value()?);
                        }
                        "2" => {
                            sa_supported_user_auth = map.next_value().unwrap_or_default();
                        }
                        "3" => {
                            // Skip crypto suites for now - use default empty vec
                            let _: serde::de::IgnoredAny = map.next_value()?;
                            sa_crypto_suites = Vec::new();
                        }
                        "4" => {
                            // Skip key definitions for now - use default empty vec
                            let _: serde::de::IgnoredAny = map.next_value()?;
                            sa_crypto_key_definition = Vec::new();
                        }
                        "5" => {
                            sa_interface = Some(map.next_value()?);
                        }
                        "6" => {
                            // Handle Tag24<ByteStr> for sa_attestation_bytes
                            match map.next_value::<SaAttestationKeyBytes>() {
                                Ok(value) => {
                                    sa_attestation_bytes = Some(value);
                                }
                                Err(_) => {
                                    sa_attestation_bytes = None;
                                }
                            }
                        }
                        "7" => {
                            sa_attestation_statement = map.next_value().ok();
                        }
                        "8" => {
                            sa_attestation_format = map.next_value().ok();
                        }
                        "9" => {
                            certification = map.next_value().unwrap_or_default();
                        }
                        _ => {
                            // Skip unknown fields
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let sa_index = sa_index.ok_or_else(|| Error::missing_field("0 (sa_index)"))?;
                let sa_interface =
                    sa_interface.ok_or_else(|| Error::missing_field("5 (sa_interface)"))?;

                println!(
                    "SaAttestationObjectValue map deserialized - sa_index: {}, sa_interface: {}",
                    sa_index, sa_interface
                );

                Ok(SaAttestationObjectValue {
                    sa_index,
                    sa_type,
                    sa_supported_user_auth,
                    sa_crypto_suites,
                    sa_crypto_key_definition,
                    sa_interface,
                    sa_attestation_bytes,
                    sa_attestation_statement,
                    sa_attestation_format,
                    certification,
                })
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let sa_index = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(0, &"at least 1 element"))?;
                let sa_type = seq.next_element()?.unwrap_or(None);
                let sa_supported_user_auth = seq.next_element()?.unwrap_or_default();
                let sa_crypto_suites = Vec::new(); // Skip for now
                let sa_crypto_key_definition = Vec::new(); // Skip for now
                let sa_interface = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(5, &"at least 6 elements"))?;
                let sa_attestation_bytes = seq.next_element()?.unwrap_or(None);
                let sa_attestation_statement = seq.next_element()?.unwrap_or(None);
                let sa_attestation_format = seq.next_element()?.unwrap_or(None);
                let certification = seq.next_element()?.unwrap_or_default();

                Ok(SaAttestationObjectValue {
                    sa_index,
                    sa_type,
                    sa_supported_user_auth,
                    sa_crypto_suites,
                    sa_crypto_key_definition,
                    sa_interface,
                    sa_attestation_bytes,
                    sa_attestation_statement,
                    sa_attestation_format,
                    certification,
                })
            }
        }

        deserializer.deserialize_any(SaAttestationObjectValueVisitor)
    }
}

impl Serialize for SaAttestationObjectValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Prefer canonical map form with "0".."9" keys
        #[derive(Serialize)]
        struct MapSer<'a> {
            #[serde(rename = "0")]
            sa_index: u64,
            #[serde(rename = "1", skip_serializing_if = "Option::is_none")]
            sa_type: &'a Option<i64>, // TODO: add a type alias for this to indicate the known types from table 8 (ISO 23220-3)
            #[serde(rename = "2", skip_serializing_if = "Vec::is_empty")]
            sa_supported_user_auth: &'a Vec<i64>,
            #[serde(
                rename = "3",
                serialize_with = "serialize_cryptosuites",
                skip_serializing_if = "Vec::is_empty"
            )]
            sa_crypto_suites: &'a SecureAreaCryptoSuites,
            #[serde(
                rename = "4",
                serialize_with = "serialize_key_definitions",
                skip_serializing_if = "Vec::is_empty"
            )]
            sa_crypto_key_definition: &'a SaCryptoKeyDefinitions,
            #[serde(rename = "5")]
            sa_interface: i64, // TODO: Add enum values based on table 10 (ISO 23220-3)
            #[serde(rename = "6", skip_serializing_if = "Option::is_none")]
            sa_attestation_bytes: &'a Option<SaAttestationKeyBytes>,
            #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
            sa_attestation_statement: &'a Option<SaAttestationStatement>,
            #[serde(rename = "8", skip_serializing_if = "Option::is_none")]
            sa_attestation_format: &'a Option<i64>,
            #[serde(rename = "9", skip_serializing_if = "Vec::is_empty")]
            certification: &'a Certifications,
        }

        MapSer {
            sa_index: self.sa_index,
            sa_type: &self.sa_type,
            sa_supported_user_auth: &self.sa_supported_user_auth,
            sa_crypto_suites: &self.sa_crypto_suites,
            sa_crypto_key_definition: &self.sa_crypto_key_definition,
            sa_interface: self.sa_interface,
            sa_attestation_bytes: &self.sa_attestation_bytes,
            sa_attestation_statement: &self.sa_attestation_statement,
            sa_attestation_format: &self.sa_attestation_format,
            certification: &self.certification,
        }
        .serialize(serializer)
    }
}

/* ------------------------------
Attestation artifacts & format
------------------------------ */

pub type SaAttestationKeyBytes = Tag24<CoseKey>;
pub type SaAttestationStatement = ByteStr;

pub mod sa_attestation_format {
    pub const JWT: i64 = 0;
}

/* ------------------------------
COSE alg/key-type id arrays
------------------------------ */

pub type SecureAreaCryptoSuites = Vec<iana::Algorithm>;

fn serialize_cryptosuites<S>(
    cryptosuites: &SecureAreaCryptoSuites,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(cryptosuites.len()))?;
    for algorithm in cryptosuites {
        seq.serialize_element(&algorithm.to_i64())?;
    }
    seq.end()
}

pub type SaCryptoKeyDefinitions = Vec<iana::KeyType>;

fn serialize_key_definitions<S>(
    key_definitions: &SaCryptoKeyDefinitions,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(key_definitions.len()))?;
    for key_type in key_definitions {
        seq.serialize_element(&key_type.to_i64())?;
    }
    seq.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MCD_BASE64_DATA: &str = r#"hFkCAKIBJhghWQH4MIIB9DCCAZmgAwIBAgIEY79y1TAKBggqhkjOPQQDAjB3MQswCQYDVQQGEwJLUjEOMAwGA1UECAwFU3V3b24xHDAaBgNVBAoME1NhbXN1bmcgRWxlY3Ryb25pY3MxFzAVBgNVBAsMDlNhbXN1bmcgV2FsbGV0MSEwHwYDVQQDDBhTYW1zdW5nIG1Eb2MgUm9vdCBDQSBTVEcwHhcNMjMwMTEyMDIzOTE3WhcNMzMwMTEyMDIzOTE3WjCBizELMAkGA1UEBhMCS1IxDjAMBgNVBAgMBVN1d29uMRwwGgYDVQQKDBNTYW1zdW5nIEVsZWN0cm9uaWNzMRcwFQYDVQQLDA5TYW1zdW5nIFdhbGxldDE1MDMGA1UEAwwsTW9iaWxlIElEIEF0dGVzdGF0aW9uIFNpZ25lciBDZXJ0aWZpY2F0ZSBTVEcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT93Dyb9MALRD87qhHyKpdsNKFek1ubmIJV2yzkRhIhFYfs/9pbob08jFy+i8Zmgp1vNGmPgcXhB6szOg81OfTHMAoGCCqGSM49BAMCA0kAMEYCIQCrJbXOp9zsRx9zTB0wfVMo0jWCT+Ug3ToybyBmDWrh/wIhANdeqqjFGn/L5WUW/TLwFdAjzEz8XXAsDX5kWJEzPZ8poFjk2BhY4KNndmVyc2lvbgF4HHNlY3VyZUFyZWFBdHRlc3RhdGlvbk9iamVjdHOBompzYUVuY29kaW5nAHgYc2FBdHRlc3RhdGlvbk9iamVjdFZhbHVlpGEwG2UEE2hARmlIYTEAYTUBYTbYGFhLpAECIAEhWCAMe68WFdJj1CXTljt6+PX/cJED6lzL9HvkfGRkC8fMkiJYIDkTS/P9ZtuStmOog+nqo6zX1FIoUNwq54zv2aIl1FNpeB1tb2JpbGVJZEFwcGxpY2F0aW9uRGVzY3JpcHRvcqNhMIEBYTGCAAFhMoEBWECY8wux+W+I24lIZY1gQPUrxScMvb1zGu5e2Tni2k80x8AhTeznZ/lt2BchW2MJ99Z802m87elMR+OTMZ1NqFri"#;

    #[test]
    fn test_mcd_deserialization_with_paths() {
        let mcd_bytes = base64::decode_config(MCD_BASE64_DATA, base64::STANDARD)
            .expect("failed to parse mcd base64 payload");

        // Extract the inner MCD bytes from the COSE structure
        let inner_mcd_bytes = extract_mcd_payload_bytes(&mcd_bytes)
            .expect("failed to extract MCD payload from COSE structure");

        let _: MobileIdCapabilityDescriptor =
            ciborium::from_reader(&inner_mcd_bytes[..]).expect("Failed to deserialize MCD");
    }

    #[test]
    fn test_working_mcd_deserialization() {
        let mcd_bytes = base64::decode_config(MCD_BASE64_DATA, base64::STANDARD)
            .expect("failed to parse mcd base64 payload");

        let inner_mcd_bytes = extract_mcd_payload_bytes(&mcd_bytes)
            .expect("failed to extract MCD payload from COSE structure");

        let _: MobileIdCapabilityDescriptor =
            ciborium::from_reader(&inner_mcd_bytes[..]).expect("failed to deserialize");
    }

    // Helper function to extract the MCD payload bytes from COSE structure
    fn extract_mcd_payload_bytes(cose_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Parse the top-level CBOR structure
        let value: ciborium::Value = ciborium::from_reader(&cose_bytes[..])?;

        // Extract from COSE array structure
        if let ciborium::Value::Array(arr) = value {
            if arr.len() >= 3 {
                if let ciborium::Value::Bytes(payload_bytes) = &arr[2] {
                    // Parse the payload as CBOR to get Tag(24, Bytes(...))
                    let payload_value: ciborium::Value = ciborium::from_reader(&payload_bytes[..])?;

                    // Extract from Tag(24, Bytes(...))
                    if let ciborium::Value::Tag(24, inner) = payload_value {
                        if let ciborium::Value::Bytes(inner_bytes) = *inner {
                            return Ok(inner_bytes);
                        }
                    }
                }
            }
        }

        Err("Could not extract MCD payload from COSE structure".into())
    }
}
