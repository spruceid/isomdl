use const_oid::db::rfc2256::STATE_OR_PROVINCE_NAME;
use error::ErrorWithContext;
use extensions::{
    key_identifier_check, validate_document_signer_certificate_extensions,
    validate_iaca_extensions, validate_mdoc_reader_certificate_extensions,
    validate_vical_signer_certificate_extensions,
};
use names::{country_name_matches, has_rdn, state_or_province_name_matches};
use serde::Serialize;
use signature::issuer_signed_subject;
use time::OffsetDateTime;
use validity::check_validity_period_at;
use x509_cert::Certificate;

use super::{
    trust_anchor::{TrustAnchorRegistry, TrustPurpose},
    util::common_name_or_unknown,
    X5Chain,
};

mod error;
mod extensions;
mod names;
pub(super) mod signature;
mod validity;

/// Options for certificate chain validation.
#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    /// The time to use for validity period checks.
    /// If `None`, the current system time is used.
    pub validation_time: Option<OffsetDateTime>,
}

impl ValidationOptions {
    /// Get the validation time, defaulting to current time if not set.
    fn validation_time(&self) -> OffsetDateTime {
        self.validation_time.unwrap_or_else(OffsetDateTime::now_utc)
    }
}

/// Ruleset for X5Chain validation.
#[derive(Debug, Clone, Copy)]
pub enum ValidationRuleset {
    /// Validate the certificate chain according to the 18013-5 rules for mDL IACA and Document
    /// Signer certificates.
    Mdl,
    /// Validate the certificate chain according to the AAMVA rules for mDL IACA and Document
    /// Signer certificates.
    AamvaMdl,
    /// Validate the certificate chain according to the 18013-5 rules for mDL Reader certificates.
    ///
    /// Only validates the leaf certificate in the x5chain against the trust anchor registry.
    MdlReaderOneStep,
    /// Validate the certificate chain for VICAL signer certificates.
    ///
    /// Validates the full certificate chain in the x5chain, where the chain must terminate at
    /// a trust anchor with `TrustPurpose::VicalAuthority`.
    Vical,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ValidationOutcome {
    pub errors: Vec<String>,
}

impl ValidationOutcome {
    pub fn success(&self) -> bool {
        self.errors.is_empty()
    }
}

impl ValidationRuleset {
    /// Validate the certificate chain with default options.
    pub fn validate(
        self,
        x5chain: &X5Chain,
        trust_anchors: &TrustAnchorRegistry,
    ) -> ValidationOutcome {
        self.validate_with_options(x5chain, trust_anchors, &ValidationOptions::default())
    }

    /// Validate the certificate chain with custom options.
    pub fn validate_with_options(
        self,
        x5chain: &X5Chain,
        trust_anchors: &TrustAnchorRegistry,
        options: &ValidationOptions,
    ) -> ValidationOutcome {
        match self {
            Self::Mdl => mdl_validate(x5chain, trust_anchors, options),
            Self::AamvaMdl => aamva_mdl_validate(x5chain, trust_anchors, options),
            Self::MdlReaderOneStep => mdl_reader_one_step_validate(x5chain, trust_anchors, options),
            Self::Vical => vical_validate(x5chain, trust_anchors, options),
        }
    }
}

fn mdl_validate_inner<'a: 'b, 'b>(
    x5chain: &'a X5Chain,
    trust_anchors: &'b TrustAnchorRegistry,
    options: &ValidationOptions,
) -> Result<(ValidationOutcome, &'a Certificate, &'b Certificate), ValidationOutcome> {
    let mut outcome = ValidationOutcome::default();
    let validation_time = options.validation_time();

    // As we are validating using the IACA rules in 18013-5, we don't need to verify the whole
    // chain. We can simply take the first certificate in the chain as the document signer
    // certificate (NOTE 1 in B.1.1).
    let document_signer = x5chain.end_entity_certificate();

    let validity_errors = check_validity_period_at(document_signer, validation_time)
        .into_iter()
        .map(ErrorWithContext::ds);
    outcome.errors.extend(validity_errors);

    let ds_extension_errors = validate_document_signer_certificate_extensions(document_signer)
        .into_iter()
        .map(ErrorWithContext::ds);
    outcome.errors.extend(ds_extension_errors);

    let mut trust_anchor_candidates =
        find_trust_anchor_candidates(document_signer, trust_anchors, TrustPurpose::Iaca, validation_time);

    let Some(iaca) = trust_anchor_candidates.next() else {
        outcome
            .errors
            .push(ErrorWithContext::iaca("no valid trust anchor found"));
        return Err(outcome);
    };

    if trust_anchor_candidates.next().is_some() {
        tracing::warn!("more than one trust anchor candidate found, using the first one");
    }

    if let Some(error) = country_name_matches(document_signer, iaca) {
        outcome.errors.push(ErrorWithContext::comparison(error))
    }

    let iaca_extension_errors = validate_iaca_extensions(iaca)
        .into_iter()
        .map(ErrorWithContext::iaca);
    outcome.errors.extend(iaca_extension_errors);

    // TODO: CRL check on DS and IACA.

    Ok((outcome, document_signer, iaca))
}

fn mdl_validate(
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    options: &ValidationOptions,
) -> ValidationOutcome {
    match mdl_validate_inner(x5chain, trust_anchors, options) {
        Ok((mut outcome, ds, iaca)) => {
            if has_rdn(ds, STATE_OR_PROVINCE_NAME) || has_rdn(iaca, STATE_OR_PROVINCE_NAME) {
                if let Some(error) = state_or_province_name_matches(ds, iaca) {
                    outcome.errors.push(ErrorWithContext::comparison(error))
                }
            }

            outcome
        }
        Err(outcome) => outcome,
    }
}

fn aamva_mdl_validate(
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    options: &ValidationOptions,
) -> ValidationOutcome {
    match mdl_validate_inner(x5chain, trust_anchors, options) {
        Ok((mut outcome, ds, iaca)) => {
            if let Some(error) = state_or_province_name_matches(ds, iaca) {
                outcome.errors.push(ErrorWithContext::comparison(error))
            }

            outcome
        }
        Err(outcome) => outcome,
    }
}

fn mdl_reader_one_step_validate(
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    options: &ValidationOptions,
) -> ValidationOutcome {
    let mut outcome = ValidationOutcome::default();
    let validation_time = options.validation_time();

    let reader = x5chain.end_entity_certificate();

    let validity_errors = check_validity_period_at(reader, validation_time)
        .into_iter()
        .map(ErrorWithContext::reader);
    outcome.errors.extend(validity_errors);

    let reader_extension_errors = validate_mdoc_reader_certificate_extensions(reader)
        .into_iter()
        .map(ErrorWithContext::reader);
    outcome.errors.extend(reader_extension_errors);

    let mut trust_anchor_candidates =
        find_trust_anchor_candidates(reader, trust_anchors, TrustPurpose::ReaderCa, validation_time);

    let Some(_reader_ca) = trust_anchor_candidates.next() else {
        outcome
            .errors
            .push(ErrorWithContext::reader_ca("no valid trust anchor found"));
        return outcome;
    };

    if trust_anchor_candidates.next().is_some() {
        tracing::warn!("more than one trust anchor candidate found, using the first one");
    }

    // TODO: CRL or OCSP check on reader and reader CA.

    outcome
}

/// Validate the VICAL signer certificate chain.
///
/// This validates the full certificate chain in the x5chain, where the chain must terminate at
/// a trust anchor with `TrustPurpose::VicalAuthority`. The chain can be multi-level, e.g.,
/// signer -> intermediate CA -> root CA.
fn vical_validate(
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    options: &ValidationOptions,
) -> ValidationOutcome {
    let mut outcome = ValidationOutcome::default();
    let validation_time = options.validation_time();

    // The first certificate in the chain is the VICAL signer certificate.
    let vical_signer = x5chain.end_entity_certificate();

    let validity_errors = check_validity_period_at(vical_signer, validation_time)
        .into_iter()
        .map(ErrorWithContext::vical_signer);
    outcome.errors.extend(validity_errors);

    let extension_errors = validate_vical_signer_certificate_extensions(vical_signer)
        .into_iter()
        .map(ErrorWithContext::vical_signer);
    outcome.errors.extend(extension_errors);

    // Try to find a trust anchor that matches either:
    // 1. The direct issuer of the VICAL signer (single-level chain)
    // 2. The issuer of the last certificate in the chain (multi-level chain)
    let chain_valid = validate_chain_to_trust_anchor(x5chain, trust_anchors, &mut outcome, validation_time);

    if !chain_valid {
        outcome.errors.push(ErrorWithContext::vical_authority(
            "no valid trust anchor found for certificate chain",
        ));
    }

    // TODO: CRL or OCSP check on VICAL signer and intermediates.

    outcome
}

/// Validate that the certificate chain terminates at a trust anchor.
///
/// Unlike mDL validation which assumes a single-level chain (document signer -> IACA),
/// VICAL chains can be multi-level (signer -> intermediate -> root). This function
/// validates each link in the chain and checks if the chain terminates at a trust anchor.
///
/// Returns true if the chain is valid and terminates at a trust anchor.
fn validate_chain_to_trust_anchor(
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    outcome: &mut ValidationOutcome,
    validation_time: OffsetDateTime,
) -> bool {
    let certificates: Vec<_> = x5chain.iter().collect();

    // Walk the chain from end-entity towards root, verifying each signature.
    for (i, window) in certificates.windows(2).enumerate() {
        let subject = &window[0].inner;
        let issuer = &window[1].inner;

        // Verify the chain link signature first.
        if !issuer_signed_subject(subject, issuer) {
            outcome.errors.push(ErrorWithContext::chain(format!(
                "certificate '{}' not signed by '{}'",
                common_name_or_unknown(subject),
                common_name_or_unknown(issuer)
            )));
            return false;
        }

        // Check validity of intermediate certificates.
        let validity_errors = check_validity_period_at(issuer, validation_time);
        if !validity_errors.is_empty() {
            outcome
                .errors
                .extend(validity_errors.into_iter().map(ErrorWithContext::chain));
        }

        // Check if the issuer (next cert in chain) is a trust anchor.
        // This handles chains like [signer, intermediate] where we trust the intermediate.
        if is_trusted_certificate(issuer, trust_anchors, TrustPurpose::VicalAuthority, validation_time) {
            tracing::debug!(
                "chain terminates at trust anchor at position {} ({})",
                i + 1,
                common_name_or_unknown(issuer)
            );
            return true;
        }
    }

    // Check if the last certificate in the chain is a trust anchor (self-signed root in chain).
    let last_cert = x5chain.root_entity_certificate();
    if is_trusted_certificate(last_cert, trust_anchors, TrustPurpose::VicalAuthority, validation_time) {
        tracing::debug!(
            "chain terminates at trust anchor (last cert): {}",
            common_name_or_unknown(last_cert)
        );
        return true;
    }

    // Finally, check if a trust anchor signed the last certificate in the chain.
    // This uses the same matching logic as mDL validation (key identifier + signature).
    let mut trust_anchor_candidates =
        find_trust_anchor_candidates(last_cert, trust_anchors, TrustPurpose::VicalAuthority, validation_time);

    if trust_anchor_candidates.next().is_some() {
        tracing::debug!(
            "chain terminates with external trust anchor signing last cert: {}",
            common_name_or_unknown(last_cert)
        );
        return true;
    }

    false
}

/// Check if a certificate directly matches a trust anchor.
///
/// This is used when the trust anchor certificate itself is included in the chain,
/// rather than being an external issuer. We match by subject name and public key
/// (SPKI), which is more reliable than key identifiers alone since it ensures the
/// actual keys are identical.
fn is_trusted_certificate(
    certificate: &Certificate,
    trust_anchors: &TrustAnchorRegistry,
    trust_purpose: TrustPurpose,
    validation_time: OffsetDateTime,
) -> bool {
    trust_anchors
        .anchors
        .iter()
        .filter(|anchor| anchor.purpose == trust_purpose)
        // Filter out expired trust anchors, consistent with find_trust_anchor_candidates.
        .filter(|anchor| {
            let errors = check_validity_period_at(&anchor.certificate, validation_time);
            if !errors.is_empty() {
                tracing::warn!(
                    "trust anchor '{}' is not valid: {errors:?}",
                    common_name_or_unknown(&anchor.certificate)
                );
            }
            errors.is_empty()
        })
        .any(|anchor| {
            // Check if subject names match.
            let subject_matches =
                anchor.certificate.tbs_certificate.subject == certificate.tbs_certificate.subject;

            if !subject_matches {
                return false;
            }

            // Check if public keys match.
            let pubkey_matches = anchor.certificate.tbs_certificate.subject_public_key_info
                == certificate.tbs_certificate.subject_public_key_info;

            if !pubkey_matches {
                tracing::debug!(
                    "subject names match but public keys differ for: {}",
                    common_name_or_unknown(certificate)
                );
                return false;
            }

            true
        })
}

fn find_trust_anchor_candidates<'a: 'b, 'b>(
    subject: &'a Certificate,
    trust_anchors: &'b TrustAnchorRegistry,
    trust_purpose: TrustPurpose,
    validation_time: OffsetDateTime,
) -> impl Iterator<Item = &'b Certificate> {
    trust_anchors
        .anchors
        .iter()
        .filter_map(move |anchor| {
            if trust_purpose == anchor.purpose {
                Some(&anchor.certificate)
            } else {
                None
            }
        })
        .filter(|candidate| candidate.tbs_certificate.subject == subject.tbs_certificate.issuer)
        .filter(|candidate| {
            let valid = key_identifier_check(
                candidate.tbs_certificate.extensions.iter().flatten(),
                subject.tbs_certificate.extensions.iter().flatten(),
            );
            if !valid {
                tracing::warn!("key identifier extensions did not match");
            }
            valid
        })
        .filter(|candidate| {
            let valid = issuer_signed_subject(subject, candidate);
            if !valid {
                tracing::warn!("issuer did not sign subject");
            }
            valid
        })
        .filter(move |candidate| {
            let errors = check_validity_period_at(candidate, validation_time);
            if !errors.is_empty() {
                tracing::warn!("certificate is not valid: {errors:?}");
            }
            errors.is_empty()
        })
}
