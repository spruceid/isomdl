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
    crl::{check_certificate_revocation, CrlFetcher, RevocationStatus},
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
    /// Errors encountered while checking CRL revocation status (e.g., fetch failures,
    /// parse errors, missing distribution points).
    ///
    /// These are kept separate from `errors` because they represent infrastructure
    /// failures rather than security failures. Actual certificate revocation is
    /// reported in `errors`, not here.
    pub revocation_errors: Vec<String>,
}

impl ValidationOutcome {
    pub fn success(&self) -> bool {
        self.errors.is_empty()
    }
}

impl ValidationRuleset {
    /// Validate the certificate chain with CRL revocation checking.
    ///
    /// # Arguments
    /// * `x5chain` - The certificate chain to validate
    /// * `trust_anchors` - The trust anchor registry
    /// * `crl_fetcher` - CRL fetcher for revocation checking. Use `&()` to skip CRL checks
    ///   (a warning will be added to `revocation_errors`).
    pub async fn validate<C: CrlFetcher>(
        self,
        x5chain: &X5Chain,
        trust_anchors: &TrustAnchorRegistry,
        crl_fetcher: &C,
    ) -> ValidationOutcome {
        match self {
            Self::Mdl => mdl_validate(x5chain, trust_anchors, crl_fetcher).await,
            Self::AamvaMdl => aamva_mdl_validate(x5chain, trust_anchors, crl_fetcher).await,
            Self::MdlReaderOneStep => {
                mdl_reader_one_step_validate(x5chain, trust_anchors, crl_fetcher).await
            }
        }
    }
}

async fn mdl_validate_inner<'a: 'b, 'b, C: CrlFetcher>(
    x5chain: &'a X5Chain,
    trust_anchors: &'b TrustAnchorRegistry,
    crl_fetcher: &C,
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

    // CRL check on DS certificate (signed by IACA)
    match check_certificate_revocation(crl_fetcher, document_signer, iaca).await {
        Ok(RevocationStatus::Valid) => {}
        Ok(RevocationStatus::Revoked { .. }) => {
            // Actual revocation is a hard security failure
            outcome
                .errors
                .push(ErrorWithContext::ds("certificate is revoked"));
        }
        Err(e) => {
            // Infrastructure failures are non-fatal warnings
            outcome
                .revocation_errors
                .push(ErrorWithContext::ds(e.to_string()));
        }
    }

    Ok((outcome, document_signer, iaca))
}

async fn mdl_validate<C: CrlFetcher>(
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    crl_fetcher: &C,
) -> ValidationOutcome {
    match mdl_validate_inner(x5chain, trust_anchors, crl_fetcher).await {
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

async fn aamva_mdl_validate<C: CrlFetcher>(
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    crl_fetcher: &C,
) -> ValidationOutcome {
    match mdl_validate_inner(x5chain, trust_anchors, crl_fetcher).await {
        Ok((mut outcome, ds, iaca)) => {
            if let Some(error) = state_or_province_name_matches(ds, iaca) {
                outcome.errors.push(ErrorWithContext::comparison(error))
            }

            outcome
        }
        Err(outcome) => outcome,
    }
}

async fn mdl_reader_one_step_validate<C: CrlFetcher>(
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    crl_fetcher: &C,
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

    let Some(reader_ca) = trust_anchor_candidates.next() else {
        outcome
            .errors
            .push(ErrorWithContext::reader_ca("no valid trust anchor found"));
        return outcome;
    };

    if trust_anchor_candidates.next().is_some() {
        tracing::warn!("more than one trust anchor candidate found, using the first one");
    }

    // CRL check on reader certificate (signed by Reader CA)
    match check_certificate_revocation(crl_fetcher, reader, reader_ca).await {
        Ok(RevocationStatus::Valid) => {}
        Ok(RevocationStatus::Revoked { .. }) => {
            // Actual revocation is a hard security failure
            outcome
                .errors
                .push(ErrorWithContext::reader("certificate is revoked"));
        }
        Err(e) => {
            // Infrastructure failures are non-fatal warnings
            outcome
                .revocation_errors
                .push(ErrorWithContext::reader(e.to_string()));
        }
    }

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
