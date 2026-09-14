//! All the checks in this module relate to requirements for X.509 certificates as detailed in
//! Annex B of ISO18013-5. Specifically, the requirements for extensions in IACA and mdoc signer
//! certificates are given in tables B.2 and B.4 respectively.

mod basic_constraints;
mod crl_distribution_points;
mod extended_key_usage;
mod issuer_alternative_name;
mod key_usage;
mod subject_key_identifier;

use std::ops::Deref;

use basic_constraints::BasicConstraintsValidator;
use const_oid::db;
use const_oid::AssociatedOid;
use const_oid::ObjectIdentifier;
use crl_distribution_points::{
    CrlDistributionPointsValidator, RelaxedCrlDistributionPointsValidator,
};
use der::Decode;
use extended_key_usage::document_signer_extended_key_usage_oid;
use extended_key_usage::mdoc_reader_extended_key_usage_oid;
use extended_key_usage::vical_signer_extended_key_usage_oid;
use extended_key_usage::ExtendedKeyUsageValidator;
use issuer_alternative_name::IssuerAlternativeNameValidator;
use key_usage::KeyUsageValidator;
use subject_key_identifier::SubjectKeyIdentifierValidator;
use x509_cert::ext::{
    pkix::{
        AuthorityKeyIdentifier, FreshestCrl, InhibitAnyPolicy, NameConstraints, PolicyConstraints,
        PolicyMappings, SubjectKeyIdentifier,
    },
    Extension,
};
use x509_cert::Certificate;

type Error = String;

/// Validate that the subject key identifier of the issuer and the authority key identifier of the
/// subject are present and equal.
pub fn key_identifier_check<'a, E>(issuer_extensions: E, subject_extensions: E) -> bool
where
    E: Iterator<Item = &'a Extension> + Clone,
{
    let issuer_skis = issuer_extensions.filter_map(|ext| {
        if ext.extn_id == SubjectKeyIdentifier::OID {
            SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes())
                .inspect_err(|e| tracing::warn!("failed to parse SubjectKeyIdentifier: {e}"))
                .ok()
        } else {
            None
        }
    });

    subject_extensions
        .filter_map(|ext| {
            if ext.extn_id == AuthorityKeyIdentifier::OID {
                AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
                    .inspect_err(|e| tracing::warn!("failed to parse AuthorityKeyIdentifier: {e}"))
                    .ok()
            } else {
                None
            }
        })
        .filter_map(|aki| aki.key_identifier)
        .any(|ki| {
            issuer_skis.clone().any(|ski| {
                tracing::debug!("comparing key identifiers:\n\t{ki:?}\n\t{:?}", ski.0);
                ki == ski.0
            })
        })
}

/// Validate IACA extensions according to 18013-5 Annex B.
pub fn validate_iaca_extensions(certificate: &Certificate) -> Vec<Error> {
    tracing::debug!("validating IACA extensions...");

    let extensions = certificate.tbs_certificate.extensions.iter().flatten();

    let mut errors: Vec<Error> = check_for_disallowed_x509_extensions(extensions.clone());

    errors.extend(
        ExtensionValidators::default()
            .with(SubjectKeyIdentifierValidator::from_certificate(certificate))
            .with(KeyUsageValidator::iaca())
            .with(BasicConstraintsValidator)
            .with(CrlDistributionPointsValidator)
            .with(IssuerAlternativeNameValidator)
            .validate_extensions(extensions),
    );

    errors
}

/// Validate document signer extensions according to 18013-5 Annex B.
pub fn validate_document_signer_certificate_extensions(certificate: &Certificate) -> Vec<Error> {
    tracing::debug!("validating document signer certificate extensions...");

    let extensions = certificate.tbs_certificate.extensions.iter().flatten();

    let mut errors: Vec<Error> = check_for_disallowed_x509_extensions(extensions.clone());

    errors.extend(
        ExtensionValidators::default()
            .with(SubjectKeyIdentifierValidator::from_certificate(certificate))
            .with(ExtendedKeyUsageValidator {
                expected_oid: document_signer_extended_key_usage_oid(),
            })
            .with(KeyUsageValidator::document_signer())
            .with(CrlDistributionPointsValidator)
            .with(IssuerAlternativeNameValidator)
            .validate_extensions(extensions),
    );

    errors
}

/// Validate mdoc reader extensions according to 18013-5 Annex B.
pub fn validate_mdoc_reader_certificate_extensions(certificate: &Certificate) -> Vec<Error> {
    tracing::debug!("validating mdoc_reader certificate extensions...");

    let extensions = certificate.tbs_certificate.extensions.iter().flatten();

    let mut errors: Vec<Error> = check_for_disallowed_x509_extensions(extensions.clone());

    errors.extend(
        ExtensionValidators::default()
            .with(SubjectKeyIdentifierValidator::from_certificate(certificate))
            .with(ExtendedKeyUsageValidator {
                expected_oid: mdoc_reader_extended_key_usage_oid(),
            })
            .with(KeyUsageValidator::mdoc_reader())
            .with(CrlDistributionPointsValidator)
            .with(IssuerAlternativeNameValidator)
            .validate_extensions(extensions),
    );

    errors
}

/// Validate VICAL signer certificate extensions according to 18013-5 Annex C.
///
/// VICAL signer certificates have different requirements than mDL document signer certificates:
/// - IssuerAlternativeName is not required
/// - CrlDistributionPoints: The spec says "URI for CRL distribution point", but we use a relaxed
///   validator that also accepts DirectoryName entries because the AAMVA VICAL signer certificate
///   uses DirectoryName instead of URI.
pub fn validate_vical_signer_certificate_extensions(certificate: &Certificate) -> Vec<Error> {
    tracing::debug!("validating VICAL signer certificate extensions...");

    let extensions = certificate.tbs_certificate.extensions.iter().flatten();

    let mut errors: Vec<Error> = check_for_disallowed_x509_extensions(extensions.clone());

    errors.extend(
        ExtensionValidators::default()
            .with(SubjectKeyIdentifierValidator::from_certificate(certificate))
            .with(ExtendedKeyUsageValidator {
                expected_oid: vical_signer_extended_key_usage_oid(),
            })
            .with(KeyUsageValidator::vical_signer())
            .with(RelaxedCrlDistributionPointsValidator)
            // Note: IssuerAlternativeName is not required for VICAL signer certificates.
            .validate_extensions(extensions),
    );

    errors
}

#[derive(Default)]
struct ExtensionValidators(Vec<Box<dyn ExtensionValidator>>);

struct RequiredExtension {
    found: bool,
    validator: Box<dyn ExtensionValidator>,
}

impl RequiredExtension {
    fn new(validator: Box<dyn ExtensionValidator>) -> Self {
        Self {
            found: false,
            validator,
        }
    }
}

impl Deref for RequiredExtension {
    type Target = Box<dyn ExtensionValidator>;

    fn deref(&self) -> &Self::Target {
        &self.validator
    }
}

trait ExtensionValidator {
    fn oid(&self) -> ObjectIdentifier;
    fn ext_name(&self) -> &'static str;
    fn validate(&self, extension: &Extension) -> Vec<Error>;
}

impl ExtensionValidators {
    fn with<V: ExtensionValidator + 'static>(mut self, validator: V) -> Self {
        self.0.push(Box::new(validator));
        self
    }

    fn validate_extensions<'a, Extensions>(self, extensions: Extensions) -> Vec<Error>
    where
        Extensions: IntoIterator<Item = &'a Extension>,
    {
        let mut validation_errors = vec![];

        let mut validators: Vec<RequiredExtension> =
            self.0.into_iter().map(RequiredExtension::new).collect();

        for ext in extensions {
            if let Some(validator) = validators.iter_mut().find(|validator| {
                tracing::debug!("searching for ext: '{}'", ext.extn_id);
                validator.oid() == ext.extn_id
            }) {
                tracing::debug!("validating required extension: {}", ext.extn_id);
                validation_errors.extend(
                    validator
                        .validate(ext)
                        .into_iter()
                        .map(|e| format!("{}: {e}", validator.ext_name())),
                );
                validator.found = true;
            } else if ext.critical {
                tracing::debug!(
                    "critical, non-required extension causing an error: {}",
                    ext.extn_id
                );
                validation_errors.push(format!(
                    "contains unknown critical extension: {}",
                    ext.extn_id
                ));
            } else {
                tracing::debug!("non-critical, non-required extension ignored: {ext:?}")
            }
        }

        validation_errors.extend(
            validators
                .iter()
                .filter(|v| !v.found)
                .map(|v| format!("{}: required extension not found", v.ext_name())),
        );

        validation_errors
    }
}

/// As identified in 18013-5 Annex B, section B.1.1.
///
/// The specification is unclear as to which certificates this restriction applies to, so it is
/// assumed in this library to apply to all and only to certificate profiles defined in Annex B.
fn check_for_disallowed_x509_extensions<'a, E>(extensions: E) -> Vec<Error>
where
    E: Iterator<Item = &'a Extension> + Clone,
{
    let disallowed_extensions = [
        PolicyMappings::OID,
        NameConstraints::OID,
        PolicyConstraints::OID,
        InhibitAnyPolicy::OID,
        FreshestCrl::OID,
    ];

    extensions
        .map(|e| e.extn_id)
        .filter_map(|id| {
            if disallowed_extensions.contains(&id) {
                Some(format!(
                    "extension is not allowed: {}",
                    db::DB
                        .by_oid(&id)
                        .map(|s| s.to_string())
                        .unwrap_or(id.to_string())
                ))
            } else {
                None
            }
        })
        .collect()
}
