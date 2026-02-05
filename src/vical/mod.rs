use ciborium::Value;
use coset::{iana, CoseSign1, Label};
use der::Decode;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x509_cert::Certificate;

pub use crate::definitions::x509::validation::ValidationOptions;

use crate::{
    cbor,
    cose::MaybeTagged,
    definitions::{
        device_request::DocType,
        helpers::{ByteStr, NonEmptyVec},
        namespaces::org_iso_18013_5_1::TDate,
        x509::{
            trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose},
            validation::{ValidationOutcome, ValidationRuleset},
            SupportedCurve, X5Chain,
        },
    },
};

/// Errors that can occur when parsing a VICAL.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to parse COSE_Sign1: {0}")]
    CoseParseError(#[from] cbor::CborError),
    #[error("failed to parse x5chain: {0}")]
    X5ChainParseError(#[source] anyhow::Error),
    #[error("failed to decode VICAL payload: {0}")]
    PayloadDecodeError(#[from] ciborium::de::Error<std::io::Error>),
    #[error("COSE_Sign1 has no payload")]
    MissingPayload,
    #[error("failed to parse certificate from CertificateInfo: {0}")]
    CertificateParseError(#[from] der::Error),
}

/// Errors that can occur when verifying a VICAL.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error(transparent)]
    ParseError(#[from] ParseError),
    #[error("no x5chain found in COSE_Sign1 unprotected header")]
    MissingX5Chain,
    #[error("failed to get public key from end-entity certificate: {0}")]
    PublicKeyError(#[source] anyhow::Error),
    #[error("COSE signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    #[error("certificate chain validation failed: {0:?}")]
    ChainValidationFailed(ValidationOutcome),
}

/// Result of a successful VICAL verification.
#[derive(Debug)]
pub struct VerifiedVical {
    /// The parsed VICAL structure.
    pub vical: Vical,
    /// The X.509 certificate chain used to sign the VICAL.
    pub x5chain: X5Chain,
}

pub type Extensions = Vec<(Value, Value)>;
pub type CertificateProfile = String;

/// VICAL profile as defined in C.1.7.1
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vical {
    /// The version of the device engagement.
    pub version: String,
    /// Identifies the VICAL provider
    pub vical_provider: String,
    /// date-time of VICAL issuance
    pub date: TDate,
    /// identifies the specific issue of the VICAL, shall be unique and monotonically increasing
    #[serde(rename = "vicalIssueID", skip_serializing_if = "Option::is_none")]
    pub vical_issue_id: Option<u64>,
    /// next VICAL is expected to be issued before this date-time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<TDate>,
    pub certificate_infos: Vec<CertificateInfo>,
    /// Can be used for proprietary extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    /// URL where this VICAL can be retrieved
    #[serde(rename = "vicalURL", skip_serializing_if = "Option::is_none")]
    pub vical_url: Option<String>,
}

/// Result of parsing a VICAL without verification.
#[derive(Debug)]
pub struct ParsedVical {
    /// The parsed VICAL structure.
    pub vical: Vical,
    /// The X.509 certificate chain from the COSE_Sign1 header, if present.
    pub x5chain: Option<X5Chain>,
}

impl Vical {
    /// Build a [`TrustAnchorRegistry`] from the certificates in this VICAL.
    ///
    /// Each certificate in `certificate_infos` is parsed and added as an IACA trust anchor.
    /// Certificates that fail to parse are skipped and logged as warnings.
    pub fn to_trust_anchor_registry(&self) -> TrustAnchorRegistry {
        let anchors = self
            .certificate_infos
            .iter()
            .filter_map(|info| match info.certificate() {
                Ok(cert) => Some(TrustAnchor {
                    certificate: cert,
                    purpose: TrustPurpose::Iaca,
                }),
                Err(e) => {
                    tracing::warn!(
                        "failed to parse certificate from CertificateInfo: {e}, skipping"
                    );
                    None
                }
            })
            .collect();

        TrustAnchorRegistry { anchors }
    }

    /// Parse a VICAL from its CBOR-encoded COSE_Sign1 representation without verification.
    ///
    /// This function parses the COSE_Sign1 structure and extracts the VICAL payload
    /// without verifying the signature or validating the certificate chain.
    ///
    /// Use this for inspection or when verification will be performed separately.
    /// For full verification, use [`VerifiedVical::from_bytes`] instead.
    ///
    /// # Arguments
    /// * `bytes` - The CBOR-encoded COSE_Sign1 containing the VICAL
    ///
    /// # Returns
    /// A `ParsedVical` containing the parsed VICAL and optional X5Chain.
    pub fn parse(bytes: &[u8]) -> Result<ParsedVical, ParseError> {
        let cose_sign1: MaybeTagged<CoseSign1> = cbor::from_slice(bytes)?;

        // Try to extract X5Chain from unprotected header (optional for parsing).
        let x5chain = cose_sign1
            .unprotected
            .rest
            .iter()
            .find(|x| x.0 == Label::Int(iana::HeaderParameter::X5Chain as i64))
            .map(|(_, v)| X5Chain::from_cbor(v.clone()))
            .transpose()
            .map_err(ParseError::X5ChainParseError)?;

        // Parse VICAL payload.
        let payload = cose_sign1
            .payload
            .as_ref()
            .ok_or(ParseError::MissingPayload)?;

        let vical: Vical = ciborium::from_reader(payload.as_slice())?;

        Ok(ParsedVical { vical, x5chain })
    }
}

impl VerifiedVical {
    /// Verify a VICAL from its CBOR-encoded COSE_Sign1 representation.
    ///
    /// This function:
    /// 1. Parses the COSE_Sign1 structure
    /// 2. Extracts the X.509 certificate chain from the unprotected header
    /// 3. Verifies the COSE signature using the end-entity certificate's public key
    /// 4. Validates the certificate chain against the provided trust anchor registry
    /// 5. Parses and returns the VICAL payload
    ///
    /// # Arguments
    /// * `bytes` - The CBOR-encoded COSE_Sign1 containing the VICAL
    /// * `trust_anchors` - Registry of trusted root/intermediate certificates for chain validation
    ///
    /// # Returns
    /// A `VerifiedVical` containing the parsed VICAL and the X.509 certificate chain on success.
    pub fn from_bytes(
        bytes: &[u8],
        trust_anchors: &TrustAnchorRegistry,
    ) -> Result<Self, VerificationError> {
        Self::from_bytes_with_options(bytes, trust_anchors, &ValidationOptions::default())
    }

    /// Verify a VICAL from its CBOR-encoded COSE_Sign1 representation with custom options.
    ///
    /// This is the same as [`from_bytes`](Self::from_bytes) but allows specifying custom
    /// validation options, such as a specific validation time for certificate validity checks.
    ///
    /// # Arguments
    /// * `bytes` - The CBOR-encoded COSE_Sign1 containing the VICAL
    /// * `trust_anchors` - Registry of trusted root/intermediate certificates for chain validation
    /// * `options` - Custom validation options
    ///
    /// # Returns
    /// A `VerifiedVical` containing the parsed VICAL and the X.509 certificate chain on success.
    pub fn from_bytes_with_options(
        bytes: &[u8],
        trust_anchors: &TrustAnchorRegistry,
        options: &ValidationOptions,
    ) -> Result<Self, VerificationError> {
        let cose_sign1: MaybeTagged<CoseSign1> =
            cbor::from_slice(bytes).map_err(ParseError::from)?;

        // Extract X5Chain from unprotected header (required for verification).
        let x5chain_cbor = cose_sign1
            .unprotected
            .rest
            .iter()
            .find(|x| x.0 == Label::Int(iana::HeaderParameter::X5Chain as i64))
            .ok_or(VerificationError::MissingX5Chain)?
            .1
            .clone();

        let x5chain = X5Chain::from_cbor(x5chain_cbor).map_err(ParseError::X5ChainParseError)?;

        // Verify COSE signature with the end-entity certificate's public key.
        let curve = SupportedCurve::from_certificate(x5chain.end_entity_certificate()).ok_or_else(
            || VerificationError::PublicKeyError(anyhow::anyhow!("unsupported curve")),
        )?;

        match curve {
            SupportedCurve::P256 => {
                let verifier: p256::ecdsa::VerifyingKey = x5chain
                    .end_entity_public_key()
                    .map_err(VerificationError::PublicKeyError)?;
                cose_sign1
                    .verify::<_, p256::ecdsa::Signature>(&verifier, None, None)
                    .into_result()
                    .map_err(VerificationError::SignatureVerificationFailed)?;
            }
            SupportedCurve::P384 => {
                let verifier: p384::ecdsa::VerifyingKey = x5chain
                    .end_entity_public_key()
                    .map_err(VerificationError::PublicKeyError)?;
                cose_sign1
                    .verify::<_, p384::ecdsa::Signature>(&verifier, None, None)
                    .into_result()
                    .map_err(VerificationError::SignatureVerificationFailed)?;
            }
        }

        // Validate certificate chain against trust anchors.
        let validation_outcome =
            ValidationRuleset::Vical.validate_with_options(&x5chain, trust_anchors, options);
        if !validation_outcome.success() {
            return Err(VerificationError::ChainValidationFailed(validation_outcome));
        }

        // Parse VICAL payload.
        let payload = cose_sign1
            .payload
            .as_ref()
            .ok_or(ParseError::MissingPayload)?;

        let vical: Vical =
            ciborium::from_reader(payload.as_slice()).map_err(ParseError::PayloadDecodeError)?;

        Ok(VerifiedVical { vical, x5chain })
    }
}

/// CertificateInfo profile as defined in C.1.7.1
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    /// DER-encoded X.509 certificate
    pub certificate: ByteStr,
    /// value of the serial number field of the certificate
    pub serial_number: Vec<u8>, // this is supposed to be a biguint but even u128 is too small
    /// value of the Subject Key Identifier field of the certificate
    pub ski: ByteStr,
    /// DocType for which the certificate may be used as a trust point
    pub doc_type: NonEmptyVec<DocType>,
    /// Type of certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_profile: Option<NonEmptyVec<CertificateProfile>>,
    /// Name of the certificate issuing authority
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_authority: Option<String>,
    /// ISO3166-1 or ISO3166-2 depending on the issuing authority
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_country: Option<String>,
    /// State or province name of the certificate issuing authority
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_or_province_name: Option<String>,
    /// DER-encoded Issuer field of the certificate (i.e. the complete Name structure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<ByteStr>,
    /// DER-encoded Subject field of the certificate (i.e. the complete Name structure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<ByteStr>,
    /// value of the notBefore field of the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<TDate>,
    /// value of the notAfter field of the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<TDate>,
    /// Can be used for proprietary extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
}

impl CertificateInfo {
    /// Parse the DER-encoded certificate into an X.509 Certificate.
    pub fn certificate(&self) -> Result<Certificate, ParseError> {
        Ok(Certificate::from_der(self.certificate.as_ref())?)
    }
}

#[cfg(test)]
mod test {
    use time::{Date, Month, OffsetDateTime, Time};

    use crate::definitions::x509::{
        trust_anchor::{TrustAnchor, TrustPurpose},
        x5chain::CertificateWithDer,
    };

    use super::*;

    // https://vical.dts.aamva.org/
    static AAMVA_VICAL: &[u8] =
        include_bytes!("../../test/vical/aamva-vical-2025-11-18-1763491092481.cbor");

    // Trust chain from https://vical.dts.aamva.org/trustcertificates
    static AAMVA_ROOT_CA: &[u8] = include_bytes!("../../test/vical/aamva_ca_root.crt");
    static AAMVA_INTERMEDIATE_CA: &[u8] =
        include_bytes!("../../test/vical/aamva_ca_intermediate.crt");

    /// The AAMVA VICAL signer certificate validity period:
    /// - Not Before: Apr 18 17:08:41 2023 GMT
    /// - Not After:  Apr 18 17:38:41 2026 GMT
    ///
    /// Use a fixed validation time before expiry to ensure tests remain stable.
    fn validation_time_before_expiry() -> OffsetDateTime {
        Date::from_calendar_date(2025, Month::January, 1)
            .unwrap()
            .with_time(Time::MIDNIGHT)
            .assume_utc()
    }

    /// A validation time after the AAMVA VICAL signer certificate expires (Apr 18, 2026).
    fn validation_time_after_expiry() -> OffsetDateTime {
        Date::from_calendar_date(2026, Month::April, 19)
            .unwrap()
            .with_time(Time::MIDNIGHT)
            .assume_utc()
    }

    fn aamva_trust_anchors() -> TrustAnchorRegistry {
        let root_cert = CertificateWithDer::from_pem(AAMVA_ROOT_CA)
            .expect("failed to parse root CA certificate");

        TrustAnchorRegistry {
            anchors: vec![TrustAnchor {
                certificate: root_cert.inner,
                purpose: TrustPurpose::VicalAuthority,
            }],
        }
    }

    #[test]
    fn verify_aamva_vical_with_trust_anchors() {
        // Build trust anchor registry with the root CA.
        // The chain in the COSE_Sign1 is: [signer, intermediate]
        // The root CA must be in the trust anchor registry.
        let trust_anchors = aamva_trust_anchors();
        let options = ValidationOptions {
            validation_time: Some(validation_time_before_expiry()),
        };

        let verified =
            VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &options)
                .expect("VICAL verification should succeed");

        // Verify the VICAL was parsed correctly.
        assert_eq!(verified.vical.version, "1.0");
        assert!(!verified.vical.certificate_infos.is_empty());

        println!("VICAL provider: {:?}", verified.vical.vical_provider);
        println!(
            "Signer certificate: {:?}",
            verified.x5chain.end_entity_common_name()
        );
        println!(
            "Chain root: {:?}",
            verified.x5chain.root_entity_common_name()
        );
        println!(
            "Number of certificate infos: {}",
            verified.vical.certificate_infos.len()
        );
    }

    #[test]
    fn verify_aamva_vical_with_intermediate_as_trust_anchor() {
        // Alternatively, trust the intermediate CA directly.
        let intermediate_cert = CertificateWithDer::from_pem(AAMVA_INTERMEDIATE_CA)
            .expect("failed to parse intermediate CA certificate");

        let trust_anchors = TrustAnchorRegistry {
            anchors: vec![TrustAnchor {
                certificate: intermediate_cert.inner,
                purpose: TrustPurpose::VicalAuthority,
            }],
        };
        let options = ValidationOptions {
            validation_time: Some(validation_time_before_expiry()),
        };

        let verified =
            VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &options)
                .expect("VICAL verification should succeed with intermediate as trust anchor");

        assert_eq!(verified.vical.version, "1.0");
    }

    #[test]
    fn verify_aamva_vical_fails_with_empty_trust_anchors() {
        let trust_anchors = TrustAnchorRegistry::default();
        let options = ValidationOptions {
            validation_time: Some(validation_time_before_expiry()),
        };

        let result = VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &options);

        assert!(
            matches!(result, Err(VerificationError::ChainValidationFailed(_))),
            "expected chain validation to fail with empty trust anchors, got: {result:?}"
        );
    }

    #[test]
    fn verify_aamva_vical_fails_with_unrelated_trust_anchor() {
        // Use an unrelated certificate as trust anchor - should fail validation.
        static UNRELATED_CERT: &[u8] =
            include_bytes!("../../test/presentation/isomdl_iaca_root_cert.pem");

        let unrelated_cert = CertificateWithDer::from_pem(UNRELATED_CERT)
            .expect("failed to parse unrelated certificate");

        let trust_anchors = TrustAnchorRegistry {
            anchors: vec![TrustAnchor {
                certificate: unrelated_cert.inner,
                purpose: TrustPurpose::VicalAuthority,
            }],
        };
        let options = ValidationOptions {
            validation_time: Some(validation_time_before_expiry()),
        };

        let result = VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &options);

        assert!(
            matches!(result, Err(VerificationError::ChainValidationFailed(_))),
            "expected chain validation to fail with unrelated trust anchor, got: {result:?}"
        );
    }

    #[test]
    fn verify_aamva_vical_fails_when_signer_cert_expired() {
        let trust_anchors = aamva_trust_anchors();
        let options = ValidationOptions {
            validation_time: Some(validation_time_after_expiry()),
        };

        let result = VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &options);

        assert!(
            matches!(result, Err(VerificationError::ChainValidationFailed(_))),
            "expected chain validation to fail with expired signer cert, got: {result:?}"
        );
    }

    #[test]
    fn parse_aamva_vical_without_verification() {
        let parsed = Vical::parse(AAMVA_VICAL).expect("VICAL parsing should succeed");

        assert_eq!(parsed.vical.version, "1.0");
        assert!(!parsed.vical.certificate_infos.is_empty());
        assert!(parsed.x5chain.is_some());
    }

    #[test]
    fn certificate_info_certificate_parsing() {
        let parsed = Vical::parse(AAMVA_VICAL).expect("VICAL parsing should succeed");

        let cert_info = &parsed.vical.certificate_infos[0];
        let cert = cert_info
            .certificate()
            .expect("certificate parsing should succeed");

        // Verify the certificate was parsed correctly by checking it has a subject.
        assert!(!cert.tbs_certificate.subject.is_empty());
    }

    #[test]
    fn vical_to_trust_anchor_registry() {
        let parsed = Vical::parse(AAMVA_VICAL).expect("VICAL parsing should succeed");

        let registry = parsed.vical.to_trust_anchor_registry();

        assert_eq!(registry.anchors.len(), parsed.vical.certificate_infos.len());
        for anchor in &registry.anchors {
            assert_eq!(anchor.purpose, TrustPurpose::Iaca);
        }
    }
}
