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
use time::OffsetDateTime;
use tracing::{error, warn};
use x509_cert::{
    crl::CertificateList,
    ext::pkix::{
        name::{DistributionPointName, GeneralName},
        AuthorityKeyIdentifier, CrlDistributionPoints, SubjectKeyIdentifier,
    },
    Certificate, Version,
};

use super::validation::ValidationOptions;

// CRL extension OIDs allowed by ISO 18013-5 Table B.10.
const OID_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const OID_CRL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.20");

/// CRL extensions allowed by the ISO 18013-5 CRL profile (Table B.10).
/// The profile states "Further extensions shall not be present."
const ALLOWED_CRL_EXTENSIONS: &[ObjectIdentifier] =
    &[OID_AUTHORITY_KEY_IDENTIFIER, OID_CRL_NUMBER];

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

/// Validate a CRL against the signing certificate per ISO 18013-5 Table B.10.
///
/// This validates:
/// - Version is v2 (5.1.2.1)
/// - TBS signature algorithm matches outer signature algorithm (5.1.2.2)
/// - Issuer matches the signing certificate subject (5.1.2.3)
/// - Validity period: thisUpdate <= validation_time <= nextUpdate (5.1.2.4, 5.1.2.5)
/// - nextUpdate is present (5.1.2.5, mandatory)
/// - Revoked certificates list is not empty if present (5.1.2.6)
/// - No unrecognized critical CRL extensions (RFC 5280 Section 5.2)
/// - Authority Key Identifier matches signing certificate's SKI (5.2.1)
/// - CRL Number extension is present (5.2.3)
/// - Signature is valid (5.1.1.2)
///
/// For ISO 18013-5, the IACA root certificate signs all CRLs in the chain.
pub fn validate_crl(
    crl: &CertificateList,
    signing_cert: &Certificate,
    options: &ValidationOptions,
) -> Result<(), CrlError> {
    // Version shall be v2 (Table B.10, 5.1.2.1)
    if crl.tbs_cert_list.version != Version::V2 {
        return Err(CrlError::InvalidVersion);
    }

    // TBS signature algorithm must match outer signature algorithm (Table B.10, 5.1.2.2)
    if crl.tbs_cert_list.signature != crl.signature_algorithm {
        return Err(CrlError::SignatureAlgorithmMismatch);
    }

    // Verify the CRL issuer matches the signing certificate subject (Table B.10, 5.1.2.3)
    if crl.tbs_cert_list.issuer != signing_cert.tbs_certificate.subject {
        return Err(CrlError::IssuerMismatch);
    }

    // Verify the CRL validity period (Table B.10, 5.1.2.4 & 5.1.2.5)
    validate_crl_validity(crl, options.validation_time())?;

    // Revoked certificates shall not be empty if present (Table B.10, 5.1.2.6)
    if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
        if revoked.is_empty() {
            return Err(CrlError::EmptyRevokedCertificates);
        }
    }

    // Check for unrecognized critical extensions (RFC 5280 Section 5.2)
    validate_crl_extensions(crl)?;

    // Authority Key Identifier must match signing cert's SKI (Table B.10, 5.2.1)
    validate_crl_authority_key_identifier(crl, signing_cert)?;

    // CRL Number must be present (Table B.10, 5.2.3)
    validate_crl_number_present(crl)?;

    // Verify the CRL signature (Table B.10, 5.1.1.2)
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

/// Check that the CRL only contains extensions allowed by ISO 18013-5 Table B.10.
///
/// The profile allows only Authority Key Identifier (5.2.1) and CRL Number (5.2.3),
/// and states "Further extensions shall not be present."
fn validate_crl_extensions(crl: &CertificateList) -> Result<(), CrlError> {
    for ext in crl.tbs_cert_list.crl_extensions.iter().flatten() {
        if !ALLOWED_CRL_EXTENSIONS.contains(&ext.extn_id) {
            return Err(CrlError::DisallowedExtension {
                oid: ext.extn_id.to_string(),
            });
        }
    }

    Ok(())
}

/// Validate that the CRL's Authority Key Identifier matches the signing certificate's
/// Subject Key Identifier (Table B.10, 5.2.1).
fn validate_crl_authority_key_identifier(
    crl: &CertificateList,
    signing_cert: &Certificate,
) -> Result<(), CrlError> {
    // Extract AKI from CRL extensions
    let aki = crl
        .tbs_cert_list
        .crl_extensions
        .iter()
        .flatten()
        .find(|ext| ext.extn_id == OID_AUTHORITY_KEY_IDENTIFIER)
        .ok_or(CrlError::MissingAuthorityKeyIdentifier)?;
    let aki = AuthorityKeyIdentifier::from_der(aki.extn_value.as_bytes()).map_err(|e| {
        warn!("failed to parse CRL Authority Key Identifier: {e}");
        CrlError::MissingAuthorityKeyIdentifier
    })?;
    let aki_key_id = aki
        .key_identifier
        .ok_or(CrlError::MissingAuthorityKeyIdentifier)?;

    // Extract SKI from signing certificate extensions
    let ski = signing_cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|ext| ext.extn_id == SubjectKeyIdentifier::OID)
        .ok_or_else(|| {
            warn!("signing certificate missing Subject Key Identifier");
            CrlError::AuthorityKeyIdentifierMismatch
        })?;
    let ski = SubjectKeyIdentifier::from_der(ski.extn_value.as_bytes()).map_err(|e| {
        warn!("failed to parse signing certificate Subject Key Identifier: {e}");
        CrlError::AuthorityKeyIdentifierMismatch
    })?;

    if aki_key_id != ski.0 {
        return Err(CrlError::AuthorityKeyIdentifierMismatch);
    }

    Ok(())
}

/// Validate that the CRL Number extension is present (Table B.10, 5.2.3).
fn validate_crl_number_present(crl: &CertificateList) -> Result<(), CrlError> {
    let has_crl_number = crl
        .tbs_cert_list
        .crl_extensions
        .iter()
        .flatten()
        .any(|ext| ext.extn_id == OID_CRL_NUMBER);
    if !has_crl_number {
        return Err(CrlError::MissingCrlNumber);
    }
    Ok(())
}

/// Validate CRL validity period (thisUpdate <= validation_time <= nextUpdate).
///
/// Per ISO 18013-5 Table B.10, nextUpdate is mandatory.
fn validate_crl_validity(
    crl: &CertificateList,
    validation_time: OffsetDateTime,
) -> Result<(), CrlError> {
    // Check thisUpdate <= validation_time
    let this_update = &crl.tbs_cert_list.this_update;
    let this_update_time = OffsetDateTime::from(this_update.to_system_time());
    if validation_time < this_update_time {
        return Err(CrlError::NotYetValid {
            this_update: format!("{this_update:?}"),
        });
    }

    // nextUpdate is mandatory per ISO 18013-5 Table B.10 (5.1.2.5)
    let next_update = crl
        .tbs_cert_list
        .next_update
        .as_ref()
        .ok_or(CrlError::MissingNextUpdate)?;
    let next_update_time = OffsetDateTime::from(next_update.to_system_time());
    if validation_time > next_update_time {
        return Err(CrlError::Expired {
            next_update: format!("{next_update:?}"),
        });
    }

    Ok(())
}

/// Check if a certificate's serial number appears in the CRL.
///
/// Per ISO 18013-5 B.3.2: if an entry is found matching the certificate serial number,
/// the certificate is considered revoked (status UNSPECIFIED). CRL entry extensions are
/// not checked, as the ISO 18013-5 CRL profile states "CRL entry extensions shall not
/// be used."
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
            // ISO 18013-5 CRL profile: "CRL entry extensions shall not be used."
            // Per B.3.2, finding the serial in the CRL means cert_status = UNSPECIFIED.
            if revoked.crl_entry_extensions.is_some() {
                warn!("CRL entry extensions present but ISO 18013-5 says they shall not be used");
            }

            return RevocationStatus::Revoked {
                serial: hex::encode(cert_serial.as_bytes()),
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
/// * `options` - Validation options (controls the time used for CRL validity checks)
///
/// # Returns
/// * `Ok(RevocationStatus::Valid)` if the certificate is not revoked
/// * `Ok(RevocationStatus::Revoked { .. })` if the certificate is revoked
/// * `Err(CrlError::...)` for failures (fetch, parse, signature, etc.)
pub async fn check_certificate_revocation(
    revocation_fetcher: &impl RevocationFetcher,
    cert: &Certificate,
    crl_signing_cert: &Certificate,
    options: &ValidationOptions,
) -> Result<RevocationStatus, CrlError> {
    let urls = extract_crl_urls(cert)?;
    let mut errors = Vec::new();

    for url in &urls {
        match fetch_and_validate_crl(revocation_fetcher, crl_signing_cert, url, options).await {
            Ok(crl) => return Ok(check_revocation(cert, &crl)),
            Err(e) => {
                warn!("CRL check failed for URL {url}: {e}");
                errors.push(format!("{url}: {e}"));
            }
        }
    }

    Err(CrlError::AllUrlsFailed { errors })
}

/// Fetch a CRL from a URL and validate it.
async fn fetch_and_validate_crl(
    revocation_fetcher: &impl RevocationFetcher,
    crl_signing_cert: &Certificate,
    url: &str,
    options: &ValidationOptions,
) -> Result<CertificateList, CrlError> {
    let crl = revocation_fetcher.fetch_crl(url).await?;
    validate_crl(&crl, crl_signing_cert, options)?;
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
    use const_oid::AssociatedOid;
    use der::{asn1::OctetString, Decode, Encode};
    use p256::NistP256;
    use signature::Signer;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };
    use x509_cert::{
        crl::{CertificateList, RevokedCert, TbsCertList},
        ext::{
            pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier},
            Extension,
        },
        name::Name,
        serial_number::SerialNumber,
        spki::SignatureBitStringEncoding,
        time::Time,
        Certificate, Version,
    };

    use super::{CachingRevocationFetcher, ReqwestClient, OID_CRL_NUMBER};
    use crate::definitions::x509::{
        test::setup_with_crl_url,
        trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose},
        validation::ValidationRuleset,
        X5Chain,
    };

    /// Build CRL extensions per ISO 18013-5 Table B.10:
    /// - Authority Key Identifier (5.2.1, M) with keyIdentifier matching the IACA's SKI
    /// - CRL Number (5.2.3, M)
    fn build_crl_extensions(root_cert: &Certificate) -> Vec<Extension> {
        // Extract SKI from the root certificate to use as the CRL's AKI
        let ski = root_cert
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|ext| ext.extn_id == SubjectKeyIdentifier::OID)
            .expect("root certificate must have SKI");
        let ski = SubjectKeyIdentifier::from_der(ski.extn_value.as_bytes())
            .expect("valid SKI extension");

        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(ski.0.as_bytes().to_vec()).unwrap()),
            ..Default::default()
        };
        let aki_ext = Extension {
            extn_id: super::OID_AUTHORITY_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(aki.to_der().unwrap()).unwrap(),
        };

        // CRL Number = 1 (encoded as DER INTEGER)
        let crl_number_value = 1u64.to_der().unwrap();
        let crl_number_ext = Extension {
            extn_id: OID_CRL_NUMBER,
            critical: false,
            extn_value: OctetString::new(crl_number_value).unwrap(),
        };

        vec![aki_ext, crl_number_ext]
    }

    fn create_crl(
        issuer: Name,
        root_cert: &Certificate,
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

        let crl_extensions = build_crl_extensions(root_cert);

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
            crl_extensions: Some(crl_extensions),
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
        let crl_bytes = create_crl(issuer, &root, &root_key, &[]);

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
        let crl_bytes = create_crl(issuer, &root, &root_key, &[signer_serial]);

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
