use std::collections::BTreeMap;

use serde_json::json;

use crate::definitions::{
    device_response::Document,
    session::SessionTranscript,
    x509::{
        self, revocation::RevocationFetcher, trust_anchor::TrustAnchorRegistry,
        validation::ValidationOptions, X5Chain,
    },
};

use super::authentication::{
    mdoc::{check_mso_validity, device_authentication, issuer_authentication},
    AuthenticationStatus, ResponseAuthenticationOutcome,
};

/// Validate a device response including device authentication, issuer authentication,
/// and certificate chain validation with CRL revocation checking.
///
/// # Arguments
/// * `session_transcript` - The session transcript for device authentication
/// * `trust_anchor_registry` - Registry of trusted root certificates
/// * `x5chain` - The certificate chain to validate
/// * `document` - The document to validate
/// * `namespaces` - The namespaces from the response
/// * `doc_types` - The document types from the response
/// * `revocation_fetcher` - Revocation fetcher for CRL checking. Use `&()` to skip revocation checks.
/// * `e_reader_key_private` - The reader's ephemeral private key bytes, used for ECDH with the
///   device's static authentication key (SDeviceKey) when verifying COSE_Mac0 per §9.1.3.5.
///   Ignored when the device uses COSE_Sign1.
///
/// This uses the default [`ValidationOptions`] (validity checks against the current
/// time). Use [`validate_response_with_options`] to pin the validation time.
#[allow(clippy::too_many_arguments)]
pub async fn validate_response<S, R>(
    session_transcript: S,
    trust_anchor_registry: TrustAnchorRegistry,
    x5chain: X5Chain,
    document: Document,
    namespaces: BTreeMap<String, serde_json::Value>,
    doc_types: Vec<String>,
    revocation_fetcher: &R,
    e_reader_key_private: [u8; 32],
) -> ResponseAuthenticationOutcome
where
    S: SessionTranscript + Clone,
    R: RevocationFetcher,
{
    validate_response_with_options(
        session_transcript,
        trust_anchor_registry,
        x5chain,
        document,
        namespaces,
        doc_types,
        revocation_fetcher,
        e_reader_key_private,
        &ValidationOptions::default(),
    )
    .await
}

/// Like [`validate_response`], but with explicit [`ValidationOptions`].
///
/// The `options` control the validation time used both for the certificate chain
/// validity checks and for the MSO `validityInfo` window check, which makes both
/// deterministic in tests.
#[allow(clippy::too_many_arguments)]
pub async fn validate_response_with_options<S, R>(
    session_transcript: S,
    trust_anchor_registry: TrustAnchorRegistry,
    x5chain: X5Chain,
    document: Document,
    namespaces: BTreeMap<String, serde_json::Value>,
    doc_types: Vec<String>,
    revocation_fetcher: &R,
    e_reader_key_private: [u8; 32],
    options: &ValidationOptions,
) -> ResponseAuthenticationOutcome
where
    S: SessionTranscript + Clone,
    R: RevocationFetcher,
{
    let mut validated_response = ResponseAuthenticationOutcome {
        response: namespaces,
        doc_types,
        ..Default::default()
    };

    match device_authentication(&document, session_transcript.clone(), &e_reader_key_private) {
        Ok(_) => {
            validated_response.device_authentication = AuthenticationStatus::Valid;
        }
        Err(e) => {
            validated_response.device_authentication = AuthenticationStatus::Invalid;

            validated_response.errors.insert(
                "device_authentication_errors".to_string(),
                json!(vec![format!("{e}")]),
            );
        }
    }

    let validation_outcome = x509::validation::ValidationRuleset::Mdl
        .validate_with_options(
            &x5chain,
            &trust_anchor_registry,
            revocation_fetcher,
            options,
        )
        .await;

    // Add revocation errors as warnings (non-fatal)
    if !validation_outcome.revocation_errors.is_empty() {
        validated_response.warnings.insert(
            "revocation_errors".to_string(),
            json!(validation_outcome.revocation_errors),
        );
    }

    if validation_outcome.errors.is_empty() {
        match issuer_authentication(x5chain, &document.issuer_signed) {
            Ok(mso) => {
                validated_response.issuer_authentication = AuthenticationStatus::Valid;

                // The MSO signature is trusted, so its validity window can be trusted.
                // Reject expired / not-yet-valid credentials (ISO 18013-5 §9.1.2.4).
                if let Err(e) = check_mso_validity(&mso.validity_info, options.validation_time()) {
                    validated_response.errors.insert(
                        "mso_validity_errors".to_string(),
                        json!(vec![format!("{e}")]),
                    );
                }
            }
            Err(e) => {
                validated_response.issuer_authentication = AuthenticationStatus::Invalid;
                validated_response.errors.insert(
                    "issuer_authentication_errors".to_string(),
                    serde_json::json!(vec![format!("{e}")]),
                );
            }
        }
    } else {
        validated_response.errors.insert(
            "certificate_errors".to_string(),
            json!(validation_outcome.errors),
        );
        validated_response.issuer_authentication = AuthenticationStatus::Invalid
    };

    validated_response
}
