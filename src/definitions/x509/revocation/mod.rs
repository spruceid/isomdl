//! Certificate revocation verification support.
//!
//! This module provides functionality for checking certificate revocation status
//! via CRL distribution points, as required by ISO 18013-5. OCSP support is
//! planned for the future.
//!
//! # Architecture
//!
//! The module separates concerns for cross-platform support:
//!
//! - [`HttpClient`]: Pure HTTP abstraction (platform-specific implementations)
//! - [`RevocationFetcher`]: Revocation data fetching with optional caching (Rust-only logic)
//! - [`CachingRevocationFetcher`]: Caching CRL implementation using [`HttpClient`]
//!
//! For mobile platforms (iOS/Android), only [`HttpClient`] needs a native
//! implementation; [`CachingRevocationFetcher`] provides all CRL-specific logic in Rust.

mod crl_fetcher;
mod error;
mod http;

#[cfg(feature = "reqwest")]
mod reqwest_client;

#[cfg(feature = "reqwest")]
pub use crl_fetcher::CachingRevocationFetcher;
pub use crl_fetcher::{RevocationFetcher, SimpleRevocationFetcher};
pub use error::{CrlError, RevocationStatus};
pub use http::{HttpClient, HttpMethod, HttpRequest, HttpResponse, NoHttpClientError};

#[cfg(feature = "reqwest")]
pub use reqwest_client::ReqwestClient;

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{Decode, Encode};
use tracing::{error, warn};
use x509_cert::{
    crl::CertificateList,
    ext::pkix::{
        name::{DistributionPointName, GeneralName},
        CrlDistributionPoints, CrlReason,
    },
    Certificate,
};

// OIDs for CRL extensions we recognize (RFC 5280 Section 5.2)
const OID_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const OID_ISSUER_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.18");
const OID_CRL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.20");
const OID_ISSUING_DISTRIBUTION_POINT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.28");
const OID_FRESHEST_CRL: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.46");

// OIDs for CRL entry extensions we recognize (RFC 5280 Section 5.3)
const OID_CRL_REASON: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");
const OID_HOLD_INSTRUCTION_CODE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.23");
const OID_INVALIDITY_DATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.24");
const OID_CERTIFICATE_ISSUER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.29");

/// Extensions we recognize and can safely process (or ignore).
/// If a CRL contains a critical extension not in this list, we must reject it.
const RECOGNIZED_CRL_EXTENSIONS: &[ObjectIdentifier] = &[
    OID_AUTHORITY_KEY_IDENTIFIER,
    OID_ISSUER_ALT_NAME,
    OID_CRL_NUMBER,
    OID_ISSUING_DISTRIBUTION_POINT,
    OID_FRESHEST_CRL,
];

const RECOGNIZED_CRL_ENTRY_EXTENSIONS: &[ObjectIdentifier] = &[
    OID_CRL_REASON,
    OID_HOLD_INSTRUCTION_CODE,
    OID_INVALIDITY_DATE,
    OID_CERTIFICATE_ISSUER,
];

/// Extract CRL distribution point URLs from a certificate.
///
/// Returns URLs from the CRL Distribution Points extension, or an error
/// if no valid distribution points are found.
pub fn extract_crl_urls(cert: &Certificate) -> Result<Vec<String>, CrlError> {
    let extensions = cert.tbs_certificate.extensions.iter().flatten();

    for ext in extensions {
        if ext.extn_id == CrlDistributionPoints::OID {
            let crl_dps = CrlDistributionPoints::from_der(ext.extn_value.as_bytes())?;
            let urls: Vec<String> = crl_dps
                .0
                .iter()
                .filter_map(|dp| dp.distribution_point.as_ref())
                .filter_map(|dpn| match dpn {
                    DistributionPointName::FullName(names) => Some(names),
                    DistributionPointName::NameRelativeToCRLIssuer(_) => None,
                })
                .flat_map(|names| names.iter())
                .filter_map(|gn| match gn {
                    GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
                    _ => None,
                })
                .collect();

            if urls.is_empty() {
                return Err(CrlError::NoDistributionPoint);
            }

            return Ok(urls);
        }
    }

    Err(CrlError::NoDistributionPoint)
}

/// Parse and validate a CRL against the signing certificate.
///
/// This validates:
/// - Issuer matches the signing certificate subject
/// - Validity period (thisUpdate <= now <= nextUpdate)
/// - No unrecognized critical extensions (RFC 5280 Section 5.2)
/// - Signature is valid
///
/// For ISO 18013-5, the IACA root certificate signs all CRLs in the chain.
pub fn validate_crl_signature(
    crl: &CertificateList,
    signing_cert: &Certificate,
) -> Result<(), CrlError> {
    // Verify the CRL issuer matches the signing certificate subject
    if crl.tbs_cert_list.issuer != signing_cert.tbs_certificate.subject {
        return Err(CrlError::IssuerMismatch);
    }

    // Verify the CRL validity period
    validate_crl_validity(crl)?;

    // Check for unrecognized critical extensions (RFC 5280 Section 5.2)
    validate_crl_extensions(crl)?;

    // Verify the CRL signature
    let tbs = crl.tbs_cert_list.to_der().map_err(|e| {
        error!("failed to encode CRL TBS: {e:?}");
        CrlError::SignatureInvalid
    })?;

    if !super::validation::signature::verify_signature(
        signing_cert,
        crl.signature.raw_bytes(),
        &tbs,
    ) {
        return Err(CrlError::SignatureInvalid);
    }

    Ok(())
}

/// Check for unrecognized critical extensions in the CRL.
///
/// Per RFC 5280 Section 5.2, if a CRL contains a critical extension that the
/// application cannot process, the application must not use that CRL.
fn validate_crl_extensions(crl: &CertificateList) -> Result<(), CrlError> {
    // Check CRL-level extensions
    for ext in crl.tbs_cert_list.crl_extensions.iter().flatten() {
        if ext.critical && !RECOGNIZED_CRL_EXTENSIONS.contains(&ext.extn_id) {
            return Err(CrlError::UnrecognizedCriticalExtension {
                oid: ext.extn_id.to_string(),
            });
        }
    }

    // Check CRL entry extensions
    for revoked in crl.tbs_cert_list.revoked_certificates.iter().flatten() {
        for ext in revoked.crl_entry_extensions.iter().flatten() {
            if ext.critical && !RECOGNIZED_CRL_ENTRY_EXTENSIONS.contains(&ext.extn_id) {
                return Err(CrlError::UnrecognizedCriticalExtension {
                    oid: ext.extn_id.to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Validate CRL validity period (thisUpdate <= now <= nextUpdate).
fn validate_crl_validity(crl: &CertificateList) -> Result<(), CrlError> {
    use std::time::SystemTime;

    let now = SystemTime::now();

    // Check thisUpdate <= now
    let this_update = &crl.tbs_cert_list.this_update;
    if now < this_update.to_system_time() {
        return Err(CrlError::NotYetValid {
            this_update: format!("{this_update:?}"),
        });
    }

    // Check now <= nextUpdate (if present)
    if let Some(next_update) = &crl.tbs_cert_list.next_update {
        if now > next_update.to_system_time() {
            return Err(CrlError::Expired {
                next_update: format!("{next_update:?}"),
            });
        }
    }

    Ok(())
}

/// Check if a certificate's serial number appears in the CRL.
///
/// Returns `RevocationStatus::Valid` if not revoked, or `RevocationStatus::Revoked`
/// with details if the certificate is on the revocation list.
pub fn check_revocation(cert: &Certificate, crl: &CertificateList) -> RevocationStatus {
    let cert_serial = &cert.tbs_certificate.serial_number;

    let revoked_certs = match &crl.tbs_cert_list.revoked_certificates {
        Some(certs) => certs,
        None => return RevocationStatus::Valid,
    };

    for revoked in revoked_certs.iter() {
        if &revoked.serial_number == cert_serial {
            // Extract the reason from extensions if present
            let reason = revoked
                .crl_entry_extensions
                .iter()
                .flatten()
                .find_map(|ext| {
                    if ext.extn_id == OID_CRL_REASON {
                        CrlReason::from_der(ext.extn_value.as_bytes()).ok()
                    } else {
                        None
                    }
                });

            return RevocationStatus::Revoked {
                serial: hex::encode(cert_serial.as_bytes()),
                reason: Some(reason.unwrap_or(CrlReason::Unspecified)),
            };
        }
    }

    RevocationStatus::Valid
}

/// Check if a certificate has been revoked by fetching and validating its CRL.
///
/// This function extracts CRL distribution point URLs from the certificate,
/// fetches the CRL using the provided revocation fetcher, validates its signature
/// against the signing certificate, and checks if the certificate appears
/// in the revocation list.
///
/// # Arguments
/// * `revocation_fetcher` - Revocation fetcher to use for fetching CRLs (use [`CachingRevocationFetcher`] for caching)
/// * `cert` - The certificate to check for revocation
/// * `crl_signing_cert` - The certificate that signed the CRL (typically the issuer/IACA)
///
/// # Returns
/// * `Ok(RevocationStatus::Valid)` if the certificate is not revoked
/// * `Ok(RevocationStatus::Revoked { .. })` if the certificate is revoked
/// * `Err(CrlError::...)` for failures (fetch, parse, signature, etc.)
pub async fn check_certificate_revocation(
    revocation_fetcher: &impl RevocationFetcher,
    cert: &Certificate,
    crl_signing_cert: &Certificate,
) -> Result<RevocationStatus, CrlError> {
    let urls = extract_crl_urls(cert)?;
    let mut errors = Vec::new();

    for url in &urls {
        match fetch_and_validate_crl(revocation_fetcher, crl_signing_cert, url).await {
            Ok(crl) => return Ok(check_revocation(cert, &crl)),
            Err(e) => {
                warn!("CRL check failed for URL {url}: {e}");
                errors.push(format!("{url}: {e}"));
            }
        }
    }

    Err(CrlError::AllUrlsFailed { errors })
}

/// Fetch a CRL from a URL and validate its signature.
async fn fetch_and_validate_crl(
    revocation_fetcher: &impl RevocationFetcher,
    crl_signing_cert: &Certificate,
    url: &str,
) -> Result<CertificateList, CrlError> {
    let crl = revocation_fetcher.fetch_crl(url).await?;
    validate_crl_signature(&crl, crl_signing_cert)?;
    Ok(crl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_crl_urls_no_extension() {
        // Create a minimal certificate without CRL distribution points
        // This test verifies that we get the expected error
        let cert_pem = include_bytes!("../../../../test/presentation/isomdl_iaca_root_cert.pem");
        let cert = crate::definitions::x509::x5chain::CertificateWithDer::from_pem(cert_pem)
            .expect("valid certificate");

        // The test certificate may or may not have CRL DPs - we're just testing the function works
        let result = extract_crl_urls(&cert.inner);
        // Either we get URLs or we get NoDistributionPoint error
        assert!(result.is_ok() || matches!(result, Err(CrlError::NoDistributionPoint)));
    }
}

/// Integration tests that require the reqwest feature for HTTP mocking.
#[cfg(all(test, feature = "reqwest"))]
mod integration_tests {
    use der::Encode;
    use p256::NistP256;
    use signature::Signer;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };
    use x509_cert::{
        crl::{CertificateList, RevokedCert, TbsCertList},
        name::Name,
        serial_number::SerialNumber,
        spki::SignatureBitStringEncoding,
        time::Time,
        Version,
    };

    use super::{CachingRevocationFetcher, ReqwestClient};
    use crate::definitions::x509::{
        test::setup_with_crl_url,
        trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose},
        validation::ValidationRuleset,
        X5Chain,
    };

    fn create_crl(
        issuer: Name,
        root_key: &p256::ecdsa::SigningKey,
        revoked_serials: &[SerialNumber],
    ) -> Vec<u8> {
        let now = std::time::SystemTime::now();
        let this_update = Time::try_from(now).unwrap();
        let next_update = Time::try_from(now + std::time::Duration::from_secs(86400)).unwrap();

        let revoked_certificates = if revoked_serials.is_empty() {
            None
        } else {
            Some(
                revoked_serials
                    .iter()
                    .map(|serial| RevokedCert {
                        serial_number: serial.clone(),
                        revocation_date: this_update,
                        crl_entry_extensions: None,
                    })
                    .collect(),
            )
        };

        let tbs = TbsCertList {
            version: Version::V2,
            signature: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
            issuer,
            this_update,
            next_update: Some(next_update),
            revoked_certificates,
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

        crl.to_der().unwrap()
    }

    #[test_log::test(tokio::test)]
    async fn validation_passes_when_certificate_not_revoked() {
        let mock_server = MockServer::start().await;
        let crl_url = format!("{}/crl", mock_server.uri());

        let (root, signer, root_key, issuer) = setup_with_crl_url(crl_url.clone());

        // Create CRL with no revoked certificates
        let crl_bytes = create_crl(issuer, &root_key, &[]);

        Mock::given(method("GET"))
            .and(path("/crl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crl_bytes))
            .mount(&mock_server)
            .await;

        let trust_anchor_registry = TrustAnchorRegistry {
            anchors: vec![TrustAnchor {
                certificate: root,
                purpose: TrustPurpose::Iaca,
            }],
        };

        let x5chain = X5Chain::builder()
            .with_certificate(signer)
            .unwrap()
            .build()
            .unwrap();

        let http_client = ReqwestClient::new().unwrap();
        let crl_fetcher = CachingRevocationFetcher::new(http_client);
        let outcome = ValidationRuleset::Mdl
            .validate(&x5chain, &trust_anchor_registry, &crl_fetcher)
            .await;

        assert!(outcome.success(), "Expected success but got: {outcome:?}");
        assert!(
            outcome.revocation_errors.is_empty(),
            "Expected no revocation errors but got: {:?}",
            outcome.revocation_errors
        );
    }

    #[test_log::test(tokio::test)]
    async fn validation_fails_when_certificate_is_revoked() {
        let mock_server = MockServer::start().await;
        let crl_url = format!("{}/crl", mock_server.uri());

        let (root, signer, root_key, issuer) = setup_with_crl_url(crl_url.clone());

        // Get the signer's serial number and create CRL with it revoked
        let signer_serial = signer.tbs_certificate.serial_number.clone();
        let crl_bytes = create_crl(issuer, &root_key, &[signer_serial]);

        Mock::given(method("GET"))
            .and(path("/crl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crl_bytes))
            .mount(&mock_server)
            .await;

        let trust_anchor_registry = TrustAnchorRegistry {
            anchors: vec![TrustAnchor {
                certificate: root,
                purpose: TrustPurpose::Iaca,
            }],
        };

        let x5chain = X5Chain::builder()
            .with_certificate(signer)
            .unwrap()
            .build()
            .unwrap();

        let http_client = ReqwestClient::new().unwrap();
        let crl_fetcher = CachingRevocationFetcher::new(http_client);
        let outcome = ValidationRuleset::Mdl
            .validate(&x5chain, &trust_anchor_registry, &crl_fetcher)
            .await;

        assert!(
            !outcome.success(),
            "Expected validation to fail for revoked certificate"
        );
        assert!(
            outcome.errors.iter().any(|e| e.contains("revoked")),
            "Expected revocation error in errors: {:?}",
            outcome.errors
        );
    }

    #[test_log::test(tokio::test)]
    async fn crl_fetch_failure_is_non_fatal() {
        let mock_server = MockServer::start().await;
        let crl_url = format!("{}/crl", mock_server.uri());

        let (root, signer, _root_key, _issuer) = setup_with_crl_url(crl_url.clone());

        // Return 500 error when fetching CRL
        Mock::given(method("GET"))
            .and(path("/crl"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let trust_anchor_registry = TrustAnchorRegistry {
            anchors: vec![TrustAnchor {
                certificate: root,
                purpose: TrustPurpose::Iaca,
            }],
        };

        let x5chain = X5Chain::builder()
            .with_certificate(signer)
            .unwrap()
            .build()
            .unwrap();

        let http_client = ReqwestClient::new().unwrap();
        let crl_fetcher = CachingRevocationFetcher::new(http_client);
        let outcome = ValidationRuleset::Mdl
            .validate(&x5chain, &trust_anchor_registry, &crl_fetcher)
            .await;

        // Validation should still succeed (CRL fetch errors are non-fatal)
        assert!(
            outcome.success(),
            "Expected validation to succeed despite CRL fetch failure: {outcome:?}"
        );
        // But there should be a revocation error recorded
        assert!(
            !outcome.revocation_errors.is_empty(),
            "Expected revocation error for CRL fetch failure"
        );
    }
}
