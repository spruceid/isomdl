use coset::iana::{self, EnumI64};
use serde::{Deserialize, Serialize};

use crate::definitions::helpers::ByteStr;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileIdCapabilityDescriptor {
    version: usize,
    mobile_id_application_descriptor: MobileIdApplicationDescriptor,
    secure_area_attestation_objects: Vec<SecureAreaAttestationObject>,
}

// MobileIdApplicationDescriptor {
// ?“0”: AppSupportedDevFeatures,
// ?”1”: AppEngagementInterface,
// ?”2”: AppDataTransmissionInterface,
// ?”3”: AppAttestationKeyBytes,
// ?”4”: Certification,
// }

#[derive(Debug, Deserialize, Serialize)]
pub struct MobileIdApplicationDescriptor {
    #[serde(rename = "0", skip_serializing_if = "Vec::is_empty")]
    app_supported_dev_features: AppSupportedDevFeatures,
    #[serde(rename = "1", skip_serializing_if = "Vec::is_empty")]
    app_engagement_interface: AppEngagementInterfaces,
    #[serde(rename = "2", skip_serializing_if = "Vec::is_empty")]
    app_data_transmission_interface: AppDataTransmissionInterfaces,
    #[serde(rename = "3", skip_serializing_if = "Option::is_none")]
    app_attestation_key_bytes: Option<AppAttestationKeyBytes>,
    #[serde(rename = "4", skip_serializing_if = "Vec::is_empty")]
    certification: Certifications,
}

pub type AppSupportedDevFeatures = Vec<AppSupportedDevFeature>;

#[derive(Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum AppSupportedDevFeature {
    WebviewFeature = 0,
    SimpleViewFeature = 1,
    Other,
}

pub type AppEngagementInterfaces = Vec<AppEngagementInterface>;

#[derive(Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum AppEngagementInterface {
    QR = 0,
    NFC = 1,
    Other,
}

pub type AppDataTransmissionInterfaces = Vec<AppDataTransmissionInterface>;

#[derive(Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum AppDataTransmissionInterface {
    NFC = 0,
    BLE = 1,
    WiFi = 2,
    Internet = 3,
    Other(i64),
}

/// The CBOR bytes-encoded MobileIdAttestationKey
pub type AppAttestationKeyBytes = ByteStr;

pub type Certifications = Vec<Certification>;

#[derive(Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum Certification {
    CommonCriteriaProtectionProfileNumber(ByteStr),
    CommonCriteriacertificationNumber(ByteStr),
    /// according to ISO 19790:2012
    CertificationNumber(ByteStr),
    SecureAreaPlatformDigitalLetterOfApprovalRef(String),
    SecureAreaApplicationDigitalLetterOfApprovalRef(String),
    SAApplicationCertification(ByteStr),
    Other(i64),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SecureAreaAttestationObject {
    #[serde(rename = "saEncoding")]
    sa_encoding: SaEncoding,
    #[serde(rename = "saAttestationObjectValue")]
    sa_attestation_object_value: SaAttestationObjectValue,
}

#[derive(Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum SaEncoding {
    // Encoded according to 7.3
    // TODO: identify what 7.3
    Default = 0,
    // SAAO profile acc. to Annex D
    SAAOAnnexD = 1,
    // ISO/IEC 7816-15
    Iso7816_15 = 2,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SaAttestationObjectValue {
    #[serde(rename = "0")]
    sa_index: u8,
    #[serde(rename = "1", skip_serializing_if = "Option::is_none")]
    sa_type: Option<SecureAreaType>,
    #[serde(rename = "2", skip_serializing_if = "Vec::is_empty")]
    sa_supported_user_auth: SecureAreaSupportedUserAuth,
    #[serde(
        rename = "3",
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_cryptosuites",
        deserialize_with = "deserialize_cryptosuites"
    )]
    sa_crypto_suites: SecureAreaCryptoSuites,
    #[serde(
        rename = "4",
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_key_definitions",
        deserialize_with = "deserialize_key_definitions"
    )]
    sa_crypto_key_definition: SaCryptoKeyDefinitions,
    #[serde(rename = "5", skip_serializing_if = "Option::is_none")]
    sa_interface: Option<SaInterface>,
    #[serde(rename = "6", skip_serializing_if = "Option::is_none")]
    sa_attestation_bytes: Option<SaAttestationKeyBytes>,
    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    sa_attestation_statement: Option<SaAttestationStatement>,
    #[serde(rename = "8", skip_serializing_if = "Option::is_none")]
    sa_attestation_format: Option<SaAttestationFormat>,
    #[serde(rename = "9", skip_serializing_if = "Vec::is_empty")]
    certification: Certifications,
}

#[derive(Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum SecureAreaType {
    EmbeddedSecureElement = 0,
    RemovableSecureElement = 1,
    IntegratedSecureElement = 2,
    ExternalSecureElement = 3,
    TEE = 4,
    SoftwareComponent = 5,
    Other(i64),
}

pub type SecureAreaSupportedUserAuth = Vec<SecureAreaSupportedUserAuthType>;

#[derive(Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum SecureAreaSupportedUserAuthType {
    // TBD, See working draft of 23220-5
    Default = 0,
    TBD = 1,
    Other(i64),
}

// NOTE: Try iana::EllipticCurive for ciphersuite if the following fails.
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

fn deserialize_cryptosuites<'de, D>(deserializer: D) -> Result<SecureAreaCryptoSuites, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{SeqAccess, Visitor};
    use std::fmt;

    struct CryptoSuitesVisitor;

    impl<'de> Visitor<'de> for CryptoSuitesVisitor {
        type Value = SecureAreaCryptoSuites;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of COSE algorithm identifiers")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut cryptosuites = Vec::new();
            while let Some(value) = seq.next_element::<i64>()? {
                if let Some(alg) = iana::Algorithm::from_i64(value) {
                    cryptosuites.push(alg);
                }
            }
            Ok(cryptosuites)
        }
    }

    deserializer.deserialize_seq(CryptoSuitesVisitor)
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

fn deserialize_key_definitions<'de, D>(deserializer: D) -> Result<SaCryptoKeyDefinitions, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{SeqAccess, Visitor};
    use std::fmt;

    struct KeyDefinitionsVisitor;

    impl<'de> Visitor<'de> for KeyDefinitionsVisitor {
        type Value = SaCryptoKeyDefinitions;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of COSE key type identifiers")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut key_definitions = Vec::new();
            while let Some(value) = seq.next_element::<i64>()? {
                if let Some(key_type) = iana::KeyType::from_i64(value) {
                    key_definitions.push(key_type);
                }
            }
            Ok(key_definitions)
        }
    }

    deserializer.deserialize_seq(KeyDefinitionsVisitor)
}

/// Secure Area Interface Type
///
/// See ISO 223220-3 Table 10.
#[derive(Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum SaInterface {
    // org.iso.23220.3.BasicSA 0 uint
    BasicSA = 0,
    // org.iso.23220.3.HPKE-SA 1 uint
    HPKESA = 1,
    // org.iso.23220.3.yyySA 2 uint
    YYYSA = 2,
    // com.android.identity_credential 3 uint
    AndroidIdenityCredential = 3,
    // org.iso.23220.3.GP-SA
    GPSA,
    // other -n uint
    Other(i64),
}

/// (bstr .cbor COSE_Key);containing the mobileIdAttestationKey.Pub
pub type SaAttestationKeyBytes = ByteStr;

/// generated attestation statement, placeholder in Annex
pub type SaAttestationStatement = ByteStr;

#[derive(Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum SaAttestationFormat {
    // JSON Web Token
    JWT = 0,
    Other(i64),
}

#[cfg(test)]
mod tests {
    use crate::{cbor, definitions::mcd::MobileIdCapabilityDescriptor};

    const MCD_BASE64_DATA: &str = r#"hFkCAKIBJhghWQH4MIIB9DCCAZmgAwIBAgIEY79y1TAKBggqhkjOPQQDAjB3MQswCQYDVQQGEwJLUjEOMAwGA1UECAwFU3V3b24xHDAaBgNVBAoME1NhbXN1bmcgRWxlY3Ryb25pY3MxFzAVBgNVBAsMDlNhbXN1bmcgV2FsbGV0MSEwHwYDVQQDDBhTYW1zdW5nIG1Eb2MgUm9vdCBDQSBTVEcwHhcNMjMwMTEyMDIzOTE3WhcNMzMwMTEyMDIzOTE3WjCBizELMAkGA1UEBhMCS1IxDjAMBgNVBAgMBVN1d29uMRwwGgYDVQQKDBNTYW1zdW5nIEVsZWN0cm9uaWNzMRcwFQYDVQQLDA5TYW1zdW5nIFdhbGxldDE1MDMGA1UEAwwsTW9iaWxlIElEIEF0dGVzdGF0aW9uIFNpZ25lciBDZXJ0aWZpY2F0ZSBTVEcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT93Dyb9MALRD87qhHyKpdsNKFek1ubmIJV2yzkRhIhFYfs/9pbob08jFy+i8Zmgp1vNGmPgcXhB6szOg81OfTHMAoGCCqGSM49BAMCA0kAMEYCIQCrJbXOp9zsRx9zTB0wfVMo0jWCT+Ug3ToybyBmDWrh/wIhANdeqqjFGn/L5WUW/TLwFdAjzEz8XXAsDX5kWJEzPZ8poFjk2BhY4KNndmVyc2lvbgF4HHNlY3VyZUFyZWFBdHRlc3RhdGlvbk9iamVjdHOBompzYUVuY29kaW5nAHgYc2FBdHRlc3RhdGlvbk9iamVjdFZhbHVlpGEwG2UEE2hARmlIYTEAYTUBYTbYGFhLpAECIAEhWCAMe68WFdJj1CXTljt6+PX/cJED6lzL9HvkfGRkC8fMkiJYIDkTS/P9ZtuStmOog+nqo6zX1FIoUNwq54zv2aIl1FNpeB1tb2JpbGVJZEFwcGxpY2F0aW9uRGVzY3JpcHRvcqNhMIEBYTGCAAFhMoEBWECY8wux+W+I24lIZY1gQPUrxScMvb1zGu5e2Tni2k80x8AhTeznZ/lt2BchW2MJ99Z802m87elMR+OTMZ1NqFri"#;

    #[test]
    fn test_mcd_serialization() {
        let mcd_bytes = base64::decode_config(MCD_BASE64_DATA, base64::STANDARD)
            .expect("failed to parse mcd base64 payload");

        let mcd: MobileIdCapabilityDescriptor =
            cbor::from_slice(&mcd_bytes).expect("failed to deserialize mcd");

        println!("Deserialized MCD: {mcd:?}");
    }
}
