//! All the checks in this module relate to requirements for IACA x509 certificates as
//! detailed in Annex B of ISO18013-5. Specifically, the requirements for values in
//! root and signer certificates are given in tables B.2 and B.4.

use std::fmt;
use std::ops::Deref;

use crate::definitions::x509::error::Error;
use const_oid::AssociatedOid;
use const_oid::ObjectIdentifier;
use der::flagset::FlagSet;
use der::Decode;
use x509_cert::ext::pkix::name::DistributionPointName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage, IssuerAltName, KeyUsage, KeyUsages,
};
use x509_cert::ext::Extension;

/// 18013-5 IACA root certificate extension checks
/// * Key Usage: 5, 6 (keyCertSign, crlSign)
/// * Basic Constraints: Pathlen:0
/// * CRL Distribution Points must have tag 0
/// * Issuer Alternative Name must be of type rfc822Name or a URI (tag 1 and tag 6)
pub fn validate_iaca_root_extensions(root_extensions: &[Extension]) -> Vec<Error> {
    tracing::debug!("validating root certificate extensions...");
    //A specific subset of x509 extensions is not allowed in IACA certificates.
    //We enter an error for every present disallowed x509 extension
    let disallowed = iaca_disallowed_x509_extensions();
    let mut x509_errors: Vec<Error> = vec![];

    for extension in root_extensions {
        if let Some(disallowed_extension) = disallowed
            .iter()
            .find(|oid| extension.extn_id.to_string() == **oid)
        {
            x509_errors.push(Error::ValidationError(format!(
                "The extension with oid: {:?} is not allowed in the IACA certificate profile",
                disallowed_extension
            )));
        }
    }

    let extension_errors = ExtensionValidators::default()
        .with(RootKeyUsageValidator)
        .with(BasicConstraintsValidator)
        .with(CrlDistributionPointsValidator { kind: Kind::Root })
        .with(IssuerAlternativeNameValidator { kind: Kind::Root })
        .validate_extensions(root_extensions.iter());

    x509_errors.extend(extension_errors);

    x509_errors
}

/// 18013-5 IACA leaf certificate extension checks
/// * Extended Key Usage: 1.0.18013.5.1.2
/// * Key Usage: 0 (digitalSignature)
/// * CRL Distribution Points must have tag 0
/// * Issuer Alternative Name must be of type rfc822Name or a URI (tag 1 and tag 6)
pub fn validate_iaca_signer_extensions(
    leaf_extensions: &[Extension],
    value_extended_key_usage: ObjectIdentifier,
) -> Vec<Error> {
    tracing::debug!("validating signer certificate extensions...");

    let disallowed = iaca_disallowed_x509_extensions();
    let mut x509_errors: Vec<Error> = vec![];

    for extension in leaf_extensions {
        if let Some(disallowed_extension) = disallowed
            .iter()
            .find(|oid| extension.extn_id.to_string() == **oid)
        {
            x509_errors.push(Error::ValidationError(format!(
                "The extension with oid: {:?} is not allowed in the IACA certificate profile",
                disallowed_extension
            )));
        }
    }

    let extension_errors = ExtensionValidators::default()
        .with(ExtendedKeyUsageValidator {
            expected_oid: value_extended_key_usage,
        })
        .with(SignerKeyUsageValidator)
        .with(CrlDistributionPointsValidator { kind: Kind::Signer })
        .with(IssuerAlternativeNameValidator { kind: Kind::Signer })
        .validate_extensions(leaf_extensions.iter());

    x509_errors.extend(extension_errors);

    x509_errors
}

#[derive(Default)]
struct ExtensionValidators(Vec<Box<dyn ExtensionValidator>>);

impl ExtensionValidators {
    fn with<V: ExtensionValidator + 'static>(mut self, validator: V) -> Self {
        self.0.push(Box::new(validator));
        self
    }
}

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
    fn matches(&self, extension: &Extension) -> bool;
    fn validate(&self, extension: &Extension) -> Vec<Error>;
    fn not_found(&self) -> Error;
}

impl ExtensionValidators {
    fn validate_extensions<'a, Extensions>(self, extensions: Extensions) -> Vec<Error>
    where
        Extensions: Iterator<Item = &'a Extension>,
    {
        let mut validation_errors = vec![];

        let mut validators: Vec<RequiredExtension> =
            self.0.into_iter().map(RequiredExtension::new).collect();

        for ext in extensions {
            if let Some(validator) = validators.iter_mut().find(|validator| {
                tracing::debug!("searching for ext: '{}'", ext.extn_id);
                validator.matches(ext)
            }) {
                tracing::debug!("validating required extension: {}", ext.extn_id);
                validation_errors.extend(validator.validate(ext));
                validator.found = true;
            } else if ext.critical {
                tracing::debug!(
                    "critical, non-required extension causing an error: {}",
                    ext.extn_id
                );
                validation_errors.push(Error::ValidationError(format!(
                    "certificate contains unknown critical extension: {}",
                    ext.extn_id
                )));
            } else {
                tracing::debug!("non-critical, non-required extension ignored: {ext:?}")
            }
        }

        validation_errors.extend(
            validators
                .iter()
                .filter(|v| !v.found)
                .map(|v| v.not_found()),
        );

        validation_errors
    }
}

struct ExtendedKeyUsageValidator {
    expected_oid: ObjectIdentifier,
}

impl ExtensionValidator for ExtendedKeyUsageValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id == ExtendedKeyUsage::OID
    }

    /*  A root certificate should have KeyCertSign and CRLSign set for key usage,
    but no other key usages are allowed */
    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let extended_key_usage = ExtendedKeyUsage::from_der(&bytes);

        if !extension.critical {
            tracing::warn!(
                "expected ExtendedKeyUsage extension to be critical on signer certificate",
            )
        }

        match extended_key_usage {
            Ok(eku) => {
                if !eku.0.into_iter().all(|oid| oid == self.expected_oid) {
                    return vec![Error::ValidationError(format!(
                        "Invalid extended key usage, expected: {}",
                        self.expected_oid
                    ))];
                };
                vec![]
            }
            Err(e) => {
                vec![Error::DecodingError(e.to_string())]
            }
        }
    }

    fn not_found(&self) -> Error {
        Error::ValidationError(
            "Missing critical ExtendedKeyUsage extension in the signer certificate".to_string(),
        )
    }
}

struct SignerKeyUsageValidator;

impl ExtensionValidator for SignerKeyUsageValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id == KeyUsage::OID
    }

    /*  A root certificate should have KeyCertSign and CRLSign set for key usage,
    but no other key usages are allowed */
    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let mut errors: Vec<Error> = vec![];
        let key_usage = KeyUsage::from_der(&bytes);

        if !extension.critical {
            tracing::warn!("expected KeyUsage extension to be critical on signer certificate",)
        }

        match key_usage {
            Ok(ku) => {
                let expected_flagset: FlagSet<KeyUsages> = KeyUsages::DigitalSignature.into();
                if ku.0 != expected_flagset {
                    errors.push(Error::ValidationError(
                        "Signer KeyUsage should be set to DigitalSignature only".into(),
                    ))
                }
            }
            Err(e) => {
                errors.push(e.into());
            }
        };
        errors
    }

    fn not_found(&self) -> Error {
        Error::ValidationError(
            "Missing critical KeyUsage extension in the signer certificate".to_string(),
        )
    }
}

struct RootKeyUsageValidator;

impl ExtensionValidator for RootKeyUsageValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id == KeyUsage::OID
    }

    /*  A root certificate should have KeyCertSign and CRLSign set for key usage,
    but no other key usages are allowed */
    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let mut errors = vec![];
        let key_usage = KeyUsage::from_der(bytes);

        if !extension.critical {
            tracing::warn!("expected KeyUsage extension to be critical on root certificate",)
        }

        match key_usage {
            Ok(ku) => {
                if !ku.crl_sign() {
                    errors.push(Error::ValidationError(
                        "CrlSign should be set on the root certificate key usage".to_string(),
                    ))
                };
                if !ku.key_cert_sign() {
                    errors.push(Error::ValidationError(
                        "KeyCertSign should be set on the root certificate key usage".to_string(),
                    ))
                };

                if ku
                    .0
                    .into_iter()
                    .any(|flag| flag != KeyUsages::CRLSign && flag != KeyUsages::KeyCertSign)
                {
                    errors.push(Error::ValidationError(format!("The key usage of the root certificate goes beyond the scope of IACA root certificates {:?}", ku)))
                };
                errors
            }
            Err(e) => {
                vec![Error::DecodingError(e.to_string())]
            }
        }
    }

    fn not_found(&self) -> Error {
        Error::ValidationError(
            "Missing critical KeyUsage extension in the root certificate".to_string(),
        )
    }
}

struct BasicConstraintsValidator;

impl BasicConstraintsValidator {
    fn check(constraints: BasicConstraints) -> Option<Error> {
        if constraints
            .path_len_constraint
            .is_none_or(|path_len| path_len != 0)
            || !constraints.ca
        {
            Some(Error::ValidationError(format!(
                "Basic constraints expected to be CA:true, path_len:0, but found: {:?}",
                constraints
            )))
        } else {
            None
        }
    }
}

impl ExtensionValidator for BasicConstraintsValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id == BasicConstraints::OID
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let mut errors = vec![];

        if !extension.critical {
            tracing::warn!("expected BasicConstraints extension to be critical on root certificate",)
        }

        let bytes = extension.extn_value.as_bytes();
        let basic_constraints = BasicConstraints::from_der(&bytes);
        match basic_constraints {
            Ok(bc) => {
                if let Some(e) = Self::check(bc) {
                    errors.push(e);
                }
            }
            Err(e) => errors.push(Error::DecodingError(e.to_string())),
        }

        errors
    }

    fn not_found(&self) -> Error {
        Error::ValidationError(
            "The root certificate is expected to have BasicConstraints, but the extension was not found".to_string()
        )
    }
}

struct CrlDistributionPointsValidator {
    kind: Kind,
}

impl ExtensionValidator for CrlDistributionPointsValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id == CrlDistributionPoints::OID
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let mut errors: Vec<Error> = vec![];
        let crl_distribution_point = CrlDistributionPoints::from_der(&bytes);
        match crl_distribution_point {
            Ok(crl_dp) => {
                if crl_dp.0.is_empty() {
                    errors.push(Error::ValidationError(
                        "expected one or more CRL distribution points".into(),
                    ));
                }
                for point in crl_dp.0.into_iter() {
                    if point.crl_issuer.is_some() {
                        errors.push(Error::ValidationError(format!("crl_issuer may not be set on CrlDistributionPoints, but is set for: {point:?}")))
                    }

                    if point.reasons.is_some() {
                        errors.push(Error::ValidationError(format!(
                            "reasons may not be set on CrlDistributionPoints, but is set for: {point:?}",
                        )))
                    }

                    if !point
                        .distribution_point
                        .as_ref()
                        .is_some_and(|dpn| match dpn {
                            DistributionPointName::FullName(names) => {
                                let type_errors: Vec<Error> = check_general_name_types(names);
                                type_errors.is_empty()
                            }
                            DistributionPointName::NameRelativeToCRLIssuer(_) => false,
                        })
                    {
                        errors.push(Error::ValidationError(format!(
                            "crl distribution point has an invalid type: {:?}",
                            point
                        )))
                    }
                }
            }
            Err(e) => errors.push(Error::DecodingError(e.to_string())),
        }

        errors
    }

    fn not_found(&self) -> Error {
        Error::ValidationError(format!("The {} certificate is expected to have CRLDistributionPoints, but the extension was not found", self.kind))
    }
}

struct IssuerAlternativeNameValidator {
    kind: Kind,
}

impl ExtensionValidator for IssuerAlternativeNameValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id == IssuerAltName::OID
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let iss_altname = IssuerAltName::from_der(bytes);
        match iss_altname {
            Ok(ian) => check_general_name_types(&ian.0),
            Err(e) => {
                vec![Error::DecodingError(e.to_string())]
            }
        }
    }

    fn not_found(&self) -> Error {
        Error::ValidationError(format!(
            "The {} certificate is expected to have issuer alternative name specified, but the extension was not found", self.kind)
        )
    }
}

enum Kind {
    Root,
    Signer,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Root => "root",
                Self::Signer => "signer",
            }
        )
    }
}

fn check_general_name_types(names: &[GeneralName]) -> Vec<Error> {
    let valid_types: Vec<bool> = names
        .iter()
        .map(|name| {
            matches!(
                name,
                GeneralName::Rfc822Name(_) | GeneralName::UniformResourceIdentifier(_)
            )
        })
        .collect();

    if valid_types.contains(&false) {
        vec![Error::ValidationError(format!(
            "Invalid type found in GeneralNames: {:?}",
            names
        ))]
    } else {
        vec![]
    }
}

fn iaca_disallowed_x509_extensions() -> Vec<String> {
    vec![
        "2.5.29.30".to_string(),
        "2.5.29.33".to_string(),
        "2.5.29.36".to_string(),
        "2.5.29.46".to_string(),
        "2.5.29.54".to_string(),
    ]
}

#[cfg(test)]
pub mod test {
    use rstest::rstest;
    use x509_cert::ext::pkix::BasicConstraints;

    use super::BasicConstraintsValidator;

    #[rstest]
    #[case::ok(BasicConstraints { ca: true, path_len_constraint: Some(0) }, true)]
    #[case::ca_false(BasicConstraints { ca: false, path_len_constraint: Some(0) }, false)]
    #[case::path_none(BasicConstraints { ca: true, path_len_constraint: None }, false)]
    #[case::path_too_long(BasicConstraints { ca: true, path_len_constraint: Some(1) }, false)]
    #[case::both_wrong(BasicConstraints { ca: false, path_len_constraint: None }, false)]
    fn basic_constraints(#[case] bc: BasicConstraints, #[case] valid: bool) {
        let outcome = BasicConstraintsValidator::check(bc);
        assert_eq!(outcome.is_none(), valid)
    }
}
