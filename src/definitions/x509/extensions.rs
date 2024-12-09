//! All the checks in this module relate to requirements for IACA x509 certificates as
//! detailed in Annex B of ISO18013-5. Specifically, the requirements for values in
//! root and signer certificates are given in tables B.2 and B.4.

use std::fmt;
use std::ops::Deref;

use crate::definitions::x509::error::Error;
use const_oid::ObjectIdentifier;
use der::Decode;
use x509_cert::ext::pkix::name::DistributionPointName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage, IssuerAltName, KeyUsage, KeyUsages,
};
use x509_cert::ext::Extension;

// -- IACA X509 Extension OIDs -- //
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_ISSUER_ALTERNATIVE_NAME: &str = "2.5.29.18";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";

/// 18013-5 IACA root certificate extension checks
/// * Key Usage: 5, 6 (keyCertSign, crlSign)
/// * Basic Constraints: Pathlen:0
/// * CRL Distribution Points must have tag 0
/// * Issuer Alternative Name must be of type rfc822Name or a URI (tag 1 and tag 6)
pub fn validate_iaca_root_extensions(root_extensions: Vec<Extension>) -> Vec<Error> {
    //A specific subset of x509 extensions is not allowed in IACA certificates.
    //We enter an error for every present disallowed x509 extension
    let disallowed = iaca_disallowed_x509_extensions();
    let mut x509_errors: Vec<Error> = vec![];

    for extension in root_extensions.clone() {
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

    let critical_extension_errors = ExtensionValidators::default()
        .with(RootKeyUsageValidator)
        .with(BasicConstraintsValidator)
        .with(CrlDistributionPointsValidator { kind: Kind::Root })
        .with(IssuerAlternativeNameValidator { kind: Kind::Root })
        .validate_critical_extensions(root_extensions.iter());

    x509_errors.extend(critical_extension_errors);

    x509_errors
}

/// 18013-5 IACA leaf certificate extension checks
/// * Extended Key Usage: 1.0.18013.5.1.2
/// * Key Usage: 0 (digitalSignature)
/// * CRL Distribution Points must have tag 0
/// * Issuer Alternative Name must be of type rfc822Name or a URI (tag 1 and tag 6)
pub fn validate_iaca_signer_extensions(
    leaf_extensions: Vec<Extension>,
    value_extended_key_usage: ObjectIdentifier,
) -> Vec<Error> {
    let disallowed = iaca_disallowed_x509_extensions();
    let mut x509_errors: Vec<Error> = vec![];

    for extension in leaf_extensions.clone() {
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

    let critical_extension_errors = ExtensionValidators::default()
        .with(ExtendedKeyUsageValidator {
            expected_oid: value_extended_key_usage,
        })
        .with(SignerKeyUsageValidator)
        .with(CrlDistributionPointsValidator { kind: Kind::Signer })
        .with(IssuerAlternativeNameValidator { kind: Kind::Signer })
        .validate_critical_extensions(leaf_extensions.iter());

    x509_errors.extend(critical_extension_errors);

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

struct CriticalExtensionValidator {
    found: bool,
    validator: Box<dyn ExtensionValidator>,
}

impl CriticalExtensionValidator {
    fn new(validator: Box<dyn ExtensionValidator>) -> Self {
        Self {
            found: false,
            validator,
        }
    }
}

impl Deref for CriticalExtensionValidator {
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
    fn validate_critical_extensions<'a, Extensions>(self, extensions: Extensions) -> Vec<Error>
    where
        Extensions: Iterator<Item = &'a Extension>,
    {
        let mut validation_errors = vec![];

        let mut validators: Vec<CriticalExtensionValidator> = self
            .0
            .into_iter()
            .map(CriticalExtensionValidator::new)
            .collect();
        let mut validators_mut = validators.iter_mut();

        for ext in extensions.filter(|ext| ext.critical) {
            if let Some(validator) = validators_mut.find(|validator| validator.matches(ext)) {
                validation_errors.extend(validator.validate(ext));
                validator.found = true;
            } else {
                validation_errors.push(Error::ValidationError(format!(
                    "certificate contains unknown critical extension: {:?}",
                    ext.extn_id
                )));
            }
        }

        validation_errors.extend(validators_mut.filter(|v| !v.found).map(|v| v.not_found()));

        validation_errors
    }
}

struct ExtendedKeyUsageValidator {
    expected_oid: ObjectIdentifier,
}

impl ExtensionValidator for ExtendedKeyUsageValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id.to_string() == OID_EXTENDED_KEY_USAGE
    }

    /*  A root certificate should have KeyCertSign and CRLSign set for key usage,
    but no other key usages are allowed */
    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let extended_key_usage = ExtendedKeyUsage::from_der(&bytes);
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
        extension.extn_id.to_string() == OID_KEY_USAGE
    }

    /*  A root certificate should have KeyCertSign and CRLSign set for key usage,
    but no other key usages are allowed */
    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let mut errors: Vec<Error> = vec![];
        let key_usage = KeyUsage::from_der(&bytes);

        match key_usage {
            Ok(ku) => {
                if !ku.digital_signature() {
                    errors.push(Error::ValidationError(
                        "Signer key usage should be set to digital signature".to_string(),
                    ))
                }
                if ku
                    .0
                    .into_iter()
                    .any(|flag| flag != KeyUsages::DigitalSignature)
                {
                    errors.push(Error::ValidationError(
                        "Key usage is set beyond scope of IACA signer certificates".to_string(),
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
        extension.extn_id.to_string() == OID_KEY_USAGE
    }

    /*  A root certificate should have KeyCertSign and CRLSign set for key usage,
    but no other key usages are allowed */
    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let mut errors = vec![];
        let key_usage = KeyUsage::from_der(bytes);
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

impl ExtensionValidator for BasicConstraintsValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id.to_string() == OID_BASIC_CONSTRAINTS
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let basic_constraints = BasicConstraints::from_der(&bytes);
        match basic_constraints {
            Ok(bc) => {
                if bc.path_len_constraint.is_none_or(|path_len| path_len != 0) && bc.ca {
                    return vec![Error::ValidationError(format!(
                        "Basic constraints expected to be CA:true, path_len:0, but found: {:?}",
                        bc
                    ))];
                }
                vec![]
            }
            Err(e) => {
                vec![Error::DecodingError(e.to_string())]
            }
        }
    }

    fn not_found(&self) -> Error {
        Error::ValidationError(
            "The root certificate is expected to have critical basic constraints specificied, but the extensions was not found".to_string()
        )
    }
}

struct CrlDistributionPointsValidator {
    kind: Kind,
}

impl ExtensionValidator for CrlDistributionPointsValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id.to_string() == OID_CRL_DISTRIBUTION_POINTS
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let mut errors: Vec<Error> = vec![];
        let crl_distribution_point = CrlDistributionPoints::from_der(&bytes);
        match crl_distribution_point {
            Ok(crl_dp) => {
                for point in crl_dp.0.into_iter() {
                    if point.crl_issuer.is_some() || point.reasons.is_some() {
                        errors.push(Error::ValidationError(format!("crl_issuer and reasons may not be set on CrlDistributionPoints, but is set for: {:?}", point)))
                    }

                    if !point
                        .distribution_point
                        .clone()
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
        Error::ValidationError(format!("The {} certificate is expected to have a crl distribution point specificied, but the extension was not found", self.kind))
    }
}

struct IssuerAlternativeNameValidator {
    kind: Kind,
}

impl ExtensionValidator for IssuerAlternativeNameValidator {
    fn matches(&self, extension: &Extension) -> bool {
        extension.extn_id.to_string() == OID_ISSUER_ALTERNATIVE_NAME
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let iss_altname = IssuerAltName::from_der(bytes);
        match iss_altname {
            Ok(ian) => check_general_name_types(ian.0),
            Err(e) => {
                vec![Error::DecodingError(e.to_string())]
            }
        }
    }

    fn not_found(&self) -> Error {
        Error::ValidationError(format!(
            "The {} certificate is expected to have issuer alternative name specificied, but the extension was not found", self.kind)
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

fn check_general_name_types(names: Vec<GeneralName>) -> Vec<Error> {
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

    #[test]
    fn test_key_usage() {}
}
