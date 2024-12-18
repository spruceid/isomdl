use const_oid::db::rfc2256::STATE_OR_PROVINCE_NAME;
use error::ErrorWithContext;
use extensions::{
    key_identifier_check, validate_document_signer_certificate_extensions,
    validate_iaca_extensions, validate_mdoc_reader_certificate_extensions,
};
use names::{country_name_matches, has_rdn, state_or_province_name_matches};
use serde::Serialize;
use signature::issuer_signed_subject;
use validity::check_validity_period;
use x509_cert::Certificate;

use super::{
    trust_anchor::{TrustAnchorRegistry, TrustPurpose},
    X5Chain,
};

mod error;
mod extensions;
mod names;
pub(super) mod signature;
mod validity;

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
    pub fn validate(
        self,
        x5chain: &X5Chain,
        trust_anchors: &TrustAnchorRegistry,
    ) -> ValidationOutcome {
        match self {
            Self::Mdl => mdl_validate(x5chain, trust_anchors),
            Self::AamvaMdl => aamva_mdl_validate(x5chain, trust_anchors),
            Self::MdlReaderOneStep => mdl_reader_one_step_validate(x5chain, trust_anchors),
        }
    }
}

fn mdl_validate_inner<'a: 'b, 'b>(
    x5chain: &'a X5Chain,
    trust_anchors: &'b TrustAnchorRegistry,
) -> Result<(ValidationOutcome, &'a Certificate, &'b Certificate), ValidationOutcome> {
    let mut outcome = ValidationOutcome::default();

    // As we are validating using the IACA rules in 18013-5, we don't need to verify the whole
    // chain. We can simply take the first certificate in the chain as the document signer
    // certificate (NOTE 1 in B.1.1).
    let document_signer = x5chain.end_entity_certificate();

    let validity_errors = check_validity_period(document_signer)
        .into_iter()
        .map(ErrorWithContext::ds);
    outcome.errors.extend(validity_errors);

    let ds_extension_errors = validate_document_signer_certificate_extensions(document_signer)
        .into_iter()
        .map(ErrorWithContext::ds);
    outcome.errors.extend(ds_extension_errors);

    let mut trust_anchor_candidates =
        find_trust_anchor_candidates(document_signer, trust_anchors, TrustPurpose::Iaca);

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

fn mdl_validate(x5chain: &X5Chain, trust_anchors: &TrustAnchorRegistry) -> ValidationOutcome {
    match mdl_validate_inner(x5chain, trust_anchors) {
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

fn aamva_mdl_validate(x5chain: &X5Chain, trust_anchors: &TrustAnchorRegistry) -> ValidationOutcome {
    match mdl_validate_inner(x5chain, trust_anchors) {
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
) -> ValidationOutcome {
    let mut outcome = ValidationOutcome::default();

    let reader = x5chain.end_entity_certificate();

    let validity_errors = check_validity_period(reader)
        .into_iter()
        .map(ErrorWithContext::reader);
    outcome.errors.extend(validity_errors);

    let reader_extension_errors = validate_mdoc_reader_certificate_extensions(reader)
        .into_iter()
        .map(ErrorWithContext::reader);
    outcome.errors.extend(reader_extension_errors);

    let mut trust_anchor_candidates =
        find_trust_anchor_candidates(reader, trust_anchors, TrustPurpose::ReaderCa);

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

fn find_trust_anchor_candidates<'a: 'b, 'b>(
    subject: &'a Certificate,
    trust_anchors: &'b TrustAnchorRegistry,
    trust_purpose: TrustPurpose,
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
        .filter(|candidate| {
            let errors = check_validity_period(candidate);
            if !errors.is_empty() {
                tracing::warn!("certificate is not valid: {errors:?}");
            }
            errors.is_empty()
        })
}
