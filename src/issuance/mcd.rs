//! Implementation of MCD capability descriptor and SA-Attestation Object (SAAO) as per ISO/IEC JTC 1/SC 17/WG 4 N 4566.
use crate::cose::sign1::CoseSign1;
use serde::{Deserialize, Serialize};
use std::string::ToString;
use thiserror::Error;
use x509_cert::der::Encode;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MobileIdCapabilityDescriptor {
    pub version: u32,
    pub mobile_id_application_descriptor: MobileIdApplicationDescriptor,
    pub secure_area_attestation_objects: Vec<SecureAreaAttestationObject>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MobileIdApplicationDescriptor {
    pub app_supported_device_features: Option<Vec<u32>>,
    pub app_engagement_interfaces: Option<Vec<u32>>,
    pub app_data_transmission_interface: Option<Vec<u32>>,
    pub certifications: Option<Vec<CertificationValue>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AppSupportedDeviceFeatures {
    WebviewFeature = 0,
    SimpleViewFeature = 1,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AppEngagementInterfaces {
    QR = 0,
    Nfc = 1,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AppDataTransmissionInterface {
    Nfc = 0,
    Ble = 1,
    WiFiAware = 2,
    Internet = 3,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Certification {
    CommonCriteriaProtectionProfileNumber,
    CommonCriteriaCertificationNumber,
    #[allow(clippy::enum_variant_names)]
    CertificationNumberAccordingToISO19790_2012,
    ReferenceToDigitalLetterOfApprovalOfTheSecureAreaPlatform,
    ReferenceToDigitalLetterOfApprovalOfTheSAApplication,
    SAApplicationCertificationAccordingTo23220_6,
}

impl TryFrom<Certification> for String {
    type Error = Error;

    fn try_from(value: Certification) -> Result<Self, Self::Error> {
        match value {
            Certification::ReferenceToDigitalLetterOfApprovalOfTheSecureAreaPlatform => {
                Ok("3".to_string())
            }
            Certification::ReferenceToDigitalLetterOfApprovalOfTheSAApplication => {
                Ok("4".to_string())
            }
            _ => Err(Error::CertificationConversionError),
        }
    }
}

impl TryFrom<Certification> for Vec<u8> {
    type Error = Error;

    fn try_from(value: Certification) -> Result<Self, Self::Error> {
        match value {
            Certification::CommonCriteriaProtectionProfileNumber => b"0"
                .to_vec()
                .map_err(|_| Error::CertificationConversionError),
            Certification::CommonCriteriaCertificationNumber => b"1"
                .to_vec()
                .map_err(|_| Error::CertificationConversionError),
            Certification::CertificationNumberAccordingToISO19790_2012 => b"2"
                .to_vec()
                .map_err(|_| Error::CertificationConversionError),
            Certification::SAApplicationCertificationAccordingTo23220_6 => b"5"
                .to_vec()
                .map_err(|_| Error::CertificationConversionError),
            _ => Err(Error::CertificationConversionError),
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to convert Certification to corresponding encoding")]
    CertificationConversionError,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum CertificationValue {
    String(String),
    Number(u32),
    Bytes(Vec<u8>),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecureAreaAttestationObject {
    pub sa_encoding: u32,
    pub sa_attestation_object_value: SaAttestationObjectValue,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SaAttestationObjectValue {
    /// Unique index of SA-Application within MCD
    pub sa_index: u32,
    /// Determines a basic type of secure area according to ISO/IEC 23220-1
    pub sa_type: Option<u32>,
    /// SA provided mechanisms for user authentication
    pub sa_supported_user_auth: Option<Vec<u32>>,
    /// SA supported cryptographic protocols and key derivation mechanisms
    pub sa_crypto_suites: Option<Vec<u32>>,
    /// SA supported cryptographic primitives and key or block sizes
    pub sa_crypto_key_definition: Option<Vec<u32>>,
    /// Reference to interface specification of SA-Application to be used by discovery
    pub sa_interface: Option<u32>,
    /// Public part of attestation key of SA-Application, i.e., SA-AttestationPublicKey
    pub sa_attestation_key_bytes: Option<Vec<u8>>,
    /// Attestation statement over SA-AttestationPublicKey and SA-AttestationChallenge
    pub sa_attestation_statement: Option<Vec<u8>>,
    /// Determines structure and encoding of an attestation statement
    /// if an attestation statement is not part of SAAO (see identifier 7)
    pub sa_attestation_format: Option<u32>,
    /// List of certifications issued to the SA Applications
    pub certifications: Option<Vec<CertificationValue>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SaType {
    EmbeddedSecureElement = 0,
    RemovableSecureElement = 1,
    IntegratedSecureElement = 2,
    ExternalSecureElement = 3,
    TEEBased = 4,
    SoftwareComponent = 5,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SaInterface {
    OrgIso232203BasicSa = 0,
    OrgIso232203HpkeSa = 1,
    // OrgIso232203GpSa = 1,
    OrgIso23220_3YyySa = 2,
    ComAndroidIdentityCredential = 3,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SaAttestationFormat {
    JSONWebToken = 0,
}

#[allow(dead_code)]
pub type MobileIdCapabilityBytes = (Vec<u8>, MobileIdCapabilityDescriptor);

#[allow(dead_code)]
pub type MobileIdCapability = CoseSign1;

#[allow(dead_code)]
pub type SaEncoding = u32;

#[cfg(test)]
mod tests {
    use crate::cose::mac0::{CoseMac0, PreparedCoseMac0};
    use crate::cose::sign1::{CoseSign1, Error, PreparedCoseSign1, VerificationResult};
    use crate::cose::{mac0, SignatureAlgorithm};
    use coset::iana;
    use digest::Mac;
    use hex::FromHex;
    use hmac::Hmac;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::SecretKey;
    use sha2::Sha256;
    use signature::{SignatureEncoding, Signer};

    use super::*;

    static COSE_KEY: &str = include_str!("../../test/definitions/cose/sign1/secret_key");

    #[test]
    fn test_serialization_deserialization() {
        let app_descriptor = MobileIdApplicationDescriptor {
            app_supported_device_features: Some(vec![
                AppSupportedDeviceFeatures::SimpleViewFeature as u32,
            ]),
            app_engagement_interfaces: Some(vec![AppEngagementInterfaces::QR as u32]),
            app_data_transmission_interface: Some(vec![
                AppDataTransmissionInterface::WiFiAware as u32,
            ]),
            certifications: Some(vec![CertificationValue::String("FIPS".to_string())]),
        };

        let sa_attestation_value = SaAttestationObjectValue {
            sa_index: 0,
            sa_type: Some(SaType::EmbeddedSecureElement as u32),
            sa_supported_user_auth: Some(vec![42]),
            sa_crypto_suites: Some(vec![37]),
            sa_crypto_key_definition: Some(vec![23]),
            sa_interface: Some(SaInterface::ComAndroidIdentityCredential as u32),
            sa_attestation_key_bytes: Some(b"42".to_vec().unwrap()),
            sa_attestation_statement: Some(b"37".to_vec().unwrap()),
            sa_attestation_format: Some(SaAttestationFormat::JSONWebToken as u32),
            certifications: Some(vec![CertificationValue::String("FIPS".to_string())]),
        };

        let saao = SecureAreaAttestationObject {
            sa_encoding: 0,
            sa_attestation_object_value: sa_attestation_value,
        };

        let mcd = MobileIdCapabilityDescriptor {
            version: 1,
            mobile_id_application_descriptor: app_descriptor,
            secure_area_attestation_objects: vec![saao],
        };

        // Serialize to CBOR
        let serialized = serde_cbor::to_vec(&mcd).unwrap();
        println!("Serialized MCD: {:?}", serialized);

        // Deserialize from CBOR
        let deserialized: MobileIdCapabilityDescriptor =
            serde_cbor::from_slice(&serialized).unwrap();
        println!("Deserialized MCD: {:?}", deserialized);

        assert_eq!(mcd, deserialized);
    }

    #[test]
    fn test_signing_cose_sign1_and_verification() {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();

        let app_descriptor = MobileIdApplicationDescriptor {
            app_supported_device_features: Some(vec![
                AppSupportedDeviceFeatures::SimpleViewFeature as u32,
            ]),
            app_engagement_interfaces: Some(vec![AppEngagementInterfaces::QR as u32]),
            app_data_transmission_interface: Some(vec![
                AppDataTransmissionInterface::WiFiAware as u32,
            ]),
            certifications: Some(vec![CertificationValue::String("FIPS".to_string())]),
        };

        let sa_attestation_value = SaAttestationObjectValue {
            sa_index: 0,
            sa_type: Some(SaType::EmbeddedSecureElement as u32),
            sa_supported_user_auth: Some(vec![42]),
            sa_crypto_suites: Some(vec![37]),
            sa_crypto_key_definition: Some(vec![23]),
            sa_interface: Some(SaInterface::ComAndroidIdentityCredential as u32),
            sa_attestation_key_bytes: Some(b"42".to_vec().unwrap()),
            sa_attestation_statement: Some(b"37".to_vec().unwrap()),
            sa_attestation_format: Some(SaAttestationFormat::JSONWebToken as u32),
            certifications: Some(vec![CertificationValue::String("FIPS".to_string())]),
        };

        let saao = SecureAreaAttestationObject {
            sa_encoding: 0,
            sa_attestation_object_value: sa_attestation_value,
        };

        let mcd = MobileIdCapabilityDescriptor {
            version: 1,
            mobile_id_application_descriptor: app_descriptor,
            secure_area_attestation_objects: vec![saao],
        };

        // Serialize to CBOR
        let serialized = serde_cbor::to_vec(&mcd).unwrap();
        println!("Serialized MCD: {:?}", serialized);

        // Create a COSE_Sign1 structure
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        let unprotected = coset::HeaderBuilder::new()
            .key_id(b"11".to_vec().unwrap())
            .build();
        let builder = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected);
        let prepared =
            PreparedCoseSign1::new(builder, Some(serialized.clone()), None, true).unwrap();
        let signature_payload = prepared.signature_payload();
        let signature = sign::<SigningKey, Signature>(signature_payload, &signer).unwrap();
        let cose_sign1 = prepared.finalize(signature);

        // Serialize COSE_Sign1 to CBOR
        let cose_sign1_serialized = serde_cbor::to_vec(&cose_sign1).unwrap();
        println!("Serialized COSE_Sign1: {:?}", cose_sign1_serialized);

        // Deserialize COSE_Sign1 from CBOR
        let cose_sign1_deserialized: CoseSign1 =
            serde_cbor::from_slice(&cose_sign1_serialized).unwrap();
        println!("Deserialized COSE_Sign1: {:?}", cose_sign1_deserialized);

        // Verify the signature
        let verifier: VerifyingKey = (&signer).into();
        let verification_result = cose_sign1_deserialized.verify::<VerifyingKey, Signature>(
            &verifier,
            Some(serialized),
            None,
        );
        match &verification_result {
            VerificationResult::Success => println!("Signature verification succeeded."),
            VerificationResult::Failure(err) => {
                println!("Signature verification failed: {:?}", err)
            }
            VerificationResult::Error(err) => println!("Signature verification failed: {:?}", err),
        }

        assert!(verification_result.success());
    }

    #[test]
    fn test_tagging_cose_mac0_and_verification() {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();

        let app_descriptor = MobileIdApplicationDescriptor {
            app_supported_device_features: Some(vec![
                AppSupportedDeviceFeatures::SimpleViewFeature as u32,
            ]),
            app_engagement_interfaces: Some(vec![AppEngagementInterfaces::QR as u32]),
            app_data_transmission_interface: Some(vec![
                AppDataTransmissionInterface::WiFiAware as u32,
            ]),
            certifications: Some(vec![CertificationValue::String("FIPS".to_string())]),
        };

        let sa_attestation_value = SaAttestationObjectValue {
            sa_index: 0,
            sa_type: Some(SaType::EmbeddedSecureElement as u32),
            sa_supported_user_auth: Some(vec![42]),
            sa_crypto_suites: Some(vec![37]),
            sa_crypto_key_definition: Some(vec![23]),
            sa_interface: Some(SaInterface::ComAndroidIdentityCredential as u32),
            sa_attestation_key_bytes: Some(b"42".to_vec().unwrap()),
            sa_attestation_statement: Some(b"37".to_vec().unwrap()),
            sa_attestation_format: Some(SaAttestationFormat::JSONWebToken as u32),
            certifications: Some(vec![CertificationValue::String("FIPS".to_string())]),
        };

        let saao = SecureAreaAttestationObject {
            sa_encoding: 0,
            sa_attestation_object_value: sa_attestation_value,
        };

        let mcd = MobileIdCapabilityDescriptor {
            version: 1,
            mobile_id_application_descriptor: app_descriptor,
            secure_area_attestation_objects: vec![saao],
        };

        // Serialize to CBOR
        let serialized = serde_cbor::to_vec(&mcd).unwrap();
        println!("Serialized MCD: {:?}", serialized);

        let tagger = Hmac::<Sha256>::new_from_slice(&key).expect("failed to create HMAC signer");
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::HMAC_256_256)
            .build();
        let unprotected = coset::HeaderBuilder::new()
            .key_id(b"11".to_vec().unwrap())
            .build();
        let builder = coset::CoseMac0Builder::new()
            .protected(protected)
            .unprotected(unprotected);
        let prepared =
            PreparedCoseMac0::new(builder, Some(serialized.clone()), None, true).unwrap();
        let tag_payload = prepared.signature_payload();
        let signature = tag(tag_payload, &tagger).unwrap();
        let cose_mac0 = prepared.finalize(signature);

        // Serialize COSE_Mac0 to CBOR
        let cose_mac0_serialized = serde_cbor::to_vec(&cose_mac0).unwrap();
        println!("Serialized COSE_Mac0: {:?}", cose_mac0_serialized);

        // Deserialize COSE_Sign1 from CBOR
        let cose_mac0_deserialized: CoseMac0 =
            serde_cbor::from_slice(&cose_mac0_serialized).unwrap();
        println!("Deserialized COSE_Mac0: {:?}", cose_mac0_deserialized);

        // Verify the signature
        let verifier = Hmac::<Sha256>::new_from_slice(&key).expect("failed to create HMAC signer");
        let verification_result = cose_mac0_deserialized.verify(&verifier, Some(serialized), None);
        match &verification_result {
            mac0::VerificationResult::Success => println!("Signature verification succeeded."),
            mac0::VerificationResult::Failure(err) => {
                println!("Signature verification failed: {:?}", err)
            }
            mac0::VerificationResult::Error(err) => {
                println!("Signature verification failed: {:?}", err)
            }
        }

        assert!(verification_result.success());
    }

    fn sign<S, Sig>(signature_payload: &[u8], s: &S) -> anyhow::Result<Vec<u8>>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding,
    {
        Ok(s.try_sign(signature_payload)
            .map_err(Error::Signing)?
            .to_vec())
    }

    fn tag(signature_payload: &[u8], s: &Hmac<Sha256>) -> anyhow::Result<Vec<u8>> {
        let mut mac = s.clone();
        mac.reset();
        mac.update(signature_payload);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}
