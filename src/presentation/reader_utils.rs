use std::collections::BTreeMap;

use serde_json::json;

use crate::definitions::{
    device_response::Document,
    session::SessionTranscript,
    x509::{self, trust_anchor::TrustAnchorRegistry, X5Chain},
};

use super::authentication::{
    mdoc::{device_authentication, issuer_authentication},
    AuthenticationStatus, ResponseAuthenticationOutcome,
};

pub fn validate_response<S>(
    session_transcript: S,
    trust_anchor_registry: TrustAnchorRegistry,
    x5chain: X5Chain,
    document: Document,
    namespaces: BTreeMap<String, serde_json::Value>,
) -> ResponseAuthenticationOutcome
where
    S: SessionTranscript + Clone,
{
    let mut validated_response = ResponseAuthenticationOutcome {
        response: namespaces,
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

    let validation_errors = x509::validation::ValidationRuleset::Mdl
        .validate(&x5chain, &trust_anchor_registry)
        .errors;
    if validation_errors.is_empty() {
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
        validated_response
            .errors
            .insert("certificate_errors".to_string(), json!(validation_errors));
        validated_response.issuer_authentication = AuthenticationStatus::Invalid
    };

    validated_response
}
