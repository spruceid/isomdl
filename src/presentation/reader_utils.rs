use std::collections::BTreeMap;

use serde_json::json;

use crate::definitions::{
    device_response::Document,
    session::SessionTranscript,
    x509::{self, revocation::RevocationFetcher, trust_anchor::TrustAnchorRegistry, X5Chain},
};

use super::authentication::{
    mdoc::{device_authentication, issuer_authentication},
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
pub async fn validate_response<S, R>(
    session_transcript: S,
    trust_anchor_registry: TrustAnchorRegistry,
    x5chain: X5Chain,
    document: Document,
    namespaces: BTreeMap<String, serde_json::Value>,
    doc_types: Vec<String>,
    revocation_fetcher: &R,
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

    match device_authentication(&document, session_transcript.clone()) {
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
        .validate(&x5chain, &trust_anchor_registry, revocation_fetcher)
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
            Ok(_) => {
                validated_response.issuer_authentication = AuthenticationStatus::Valid;
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
