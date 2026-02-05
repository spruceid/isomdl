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
            crl::CrlFetcher,
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
    /// * `crl_fetcher` - CRL fetcher for revocation checking. Use `&()` to skip CRL checks.
    ///
    /// # Returns
    /// A `VerifiedVical` containing the parsed VICAL and the X.509 certificate chain on success.
    pub async fn from_bytes<C: CrlFetcher>(
        bytes: &[u8],
        trust_anchors: &TrustAnchorRegistry,
        crl_fetcher: &C,
    ) -> Result<Self, VerificationError> {
        Self::from_bytes_with_options(
            bytes,
            trust_anchors,
            crl_fetcher,
            &ValidationOptions::default(),
        )
        .await
    }

    /// Verify a VICAL from its CBOR-encoded COSE_Sign1 representation with custom options.
    ///
    /// This is the same as [`from_bytes`](Self::from_bytes) but allows specifying custom
    /// validation options, such as a specific validation time for certificate validity checks.
    ///
    /// # Arguments
    /// * `bytes` - The CBOR-encoded COSE_Sign1 containing the VICAL
    /// * `trust_anchors` - Registry of trusted root/intermediate certificates for chain validation
    /// * `crl_fetcher` - CRL fetcher for revocation checking. Use `&()` to skip CRL checks.
    /// * `options` - Custom validation options
    ///
    /// # Returns
    /// A `VerifiedVical` containing the parsed VICAL and the X.509 certificate chain on success.
    pub async fn from_bytes_with_options<C: CrlFetcher>(
        bytes: &[u8],
        trust_anchors: &TrustAnchorRegistry,
        crl_fetcher: &C,
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
        let validation_outcome = ValidationRuleset::Vical
            .validate_with_options(&x5chain, trust_anchors, crl_fetcher, options)
            .await;
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

    #[tokio::test]
    async fn verify_aamva_vical_with_trust_anchors() {
        // Build trust anchor registry with the root CA.
        // The chain in the COSE_Sign1 is: [signer, intermediate]
        // The root CA must be in the trust anchor registry.
        let trust_anchors = aamva_trust_anchors();
        let options = ValidationOptions {
            validation_time: Some(validation_time_before_expiry()),
        };

        let verified =
            VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &(), &options)
                .await
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

    #[tokio::test]
    async fn verify_aamva_vical_with_intermediate_as_trust_anchor() {
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
            VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &(), &options)
                .await
                .expect("VICAL verification should succeed with intermediate as trust anchor");

        assert_eq!(verified.vical.version, "1.0");
    }

    #[tokio::test]
    async fn verify_aamva_vical_fails_with_empty_trust_anchors() {
        let trust_anchors = TrustAnchorRegistry::default();
        let options = ValidationOptions {
            validation_time: Some(validation_time_before_expiry()),
        };

        let result =
            VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &(), &options)
                .await;

        assert!(
            matches!(result, Err(VerificationError::ChainValidationFailed(_))),
            "expected chain validation to fail with empty trust anchors, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_aamva_vical_fails_with_unrelated_trust_anchor() {
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

        let result =
            VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &(), &options)
                .await;

        assert!(
            matches!(result, Err(VerificationError::ChainValidationFailed(_))),
            "expected chain validation to fail with unrelated trust anchor, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_aamva_vical_fails_when_signer_cert_expired() {
        let trust_anchors = aamva_trust_anchors();
        let options = ValidationOptions {
            validation_time: Some(validation_time_after_expiry()),
        };

        let result =
            VerifiedVical::from_bytes_with_options(AAMVA_VICAL, &trust_anchors, &(), &options)
                .await;

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

    /// Test that VICAL validation fails when a certificate in the chain is revoked.
    ///
    /// This test uses wiremock to serve a CRL that reports the signer certificate as revoked.
    #[cfg(feature = "crl-reqwest")]
    #[test_log::test(tokio::test)]
    async fn vical_validation_fails_when_certificate_is_revoked() {
        use crate::definitions::x509::{
            crl::{CachingCrlFetcher, ReqwestClient},
            test::setup_with_crl_url,
            validation::ValidationRuleset,
            X5Chain,
        };
        use der::Encode;
        use p256::NistP256;
        use signature::Signer;
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };
        use x509_cert::{
            crl::{CertificateList, RevokedCert, TbsCertList},
            spki::SignatureBitStringEncoding,
            time::Time,
        };

        let mock_server = MockServer::start().await;
        let crl_url = format!("{}/crl", mock_server.uri());

        let (root, signer, root_key, issuer) = setup_with_crl_url(crl_url.clone());

        // Create CRL with the signer's serial number revoked
        let signer_serial = signer.tbs_certificate.serial_number.clone();
        let now = std::time::SystemTime::now();
        let this_update = Time::try_from(now).unwrap();
        let next_update = Time::try_from(now + std::time::Duration::from_secs(86400)).unwrap();

        let tbs = TbsCertList {
            version: x509_cert::Version::V2,
            signature: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
            issuer,
            this_update,
            next_update: Some(next_update),
            revoked_certificates: Some(vec![RevokedCert {
                serial_number: signer_serial,
                revocation_date: this_update,
                crl_entry_extensions: None,
            }]),
            crl_extensions: None,
        };

        let tbs_bytes = tbs.to_der().unwrap();
        let signature: ecdsa::Signature<NistP256> = root_key.sign(&tbs_bytes);

        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
            signature: signature.to_der().to_bitstring().unwrap(),
        };

        Mock::given(method("GET"))
            .and(path("/crl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crl.to_der().unwrap()))
            .mount(&mock_server)
            .await;

        let trust_anchors = TrustAnchorRegistry {
            anchors: vec![TrustAnchor {
                certificate: root,
                purpose: TrustPurpose::VicalAuthority,
            }],
        };

        let x5chain = X5Chain::builder()
            .with_certificate(signer)
            .unwrap()
            .build()
            .unwrap();

        let http_client = ReqwestClient::new().unwrap();
        let crl_fetcher = CachingCrlFetcher::new(http_client);
        let outcome = ValidationRuleset::Vical
            .validate(&x5chain, &trust_anchors, &crl_fetcher)
            .await;

        assert!(
            !outcome.success(),
            "Expected validation to fail for revoked certificate, but got: {:?}",
            outcome
        );
        assert!(
            outcome.errors.iter().any(|e| e.contains("revoked")),
            "Expected revocation error in errors: {:?}",
            outcome.errors
        );
    }

    /// Test VICAL verification with real CRL fetching against live AAMVA services.
    ///
    /// This test is ignored by default because it makes real network requests.
    /// Run with: `cargo test --features crl-reqwest verify_aamva_vical_with_live_crl -- --ignored`
    #[cfg(feature = "crl-reqwest")]
    #[tokio::test]
    #[ignore]
    async fn verify_aamva_vical_with_live_crl_fetching() {
        use crate::definitions::x509::{
            crl::{extract_crl_urls, CachingCrlFetcher, ReqwestClient},
            validation::ValidationRuleset,
        };

        let trust_anchors = aamva_trust_anchors();
        let options = ValidationOptions {
            validation_time: Some(validation_time_before_expiry()),
        };

        // Parse the VICAL first to get the x5chain for validation
        let parsed = Vical::parse(AAMVA_VICAL).expect("VICAL parsing should succeed");
        let x5chain = parsed.x5chain.as_ref().expect("x5chain should be present");

        // Check that we have CRL URLs to fetch (this ensures our test is meaningful)
        let signer_crl_urls = extract_crl_urls(x5chain.end_entity_certificate())
            .expect("signer should have CRL URLs");
        println!("Signer certificate CRL URLs: {:?}", signer_crl_urls);
        assert!(
            !signer_crl_urls.is_empty(),
            "Test requires certificates with CRL distribution points"
        );

        // Create the CRL fetcher and perform validation with CRL checking
        let http_client = ReqwestClient::new().expect("failed to create HTTP client");
        let crl_fetcher = CachingCrlFetcher::new(http_client);

        let outcome = ValidationRuleset::Vical
            .validate_with_options(x5chain, &trust_anchors, &crl_fetcher, &options)
            .await;

        // Print any revocation errors for debugging
        if !outcome.revocation_errors.is_empty() {
            println!(
                "Revocation errors (non-fatal): {:?}",
                outcome.revocation_errors
            );
        }

        // The validation should succeed (no hard errors)
        assert!(
            outcome.success(),
            "VICAL validation failed with errors: {:?}",
            outcome.errors
        );

        // CRL fetching should have succeeded without errors
        // (if there are revocation_errors, CRL fetching had issues)
        assert!(
            outcome.revocation_errors.is_empty(),
            "CRL fetching had errors: {:?}",
            outcome.revocation_errors
        );

        println!("VICAL validation succeeded with CRL checking!");
        println!("Signer certificate: {}", x5chain.end_entity_common_name());
    }
}
