use crate::definitions::x509::error::Error;
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

// -- 18013-5 IACA SPECIFIC ROOT EXTENSION VALUE CHECKS -- //
// Key Usage: 5, 6 (keyCertSign, crlSign)
// Basic Constraints: Pathlen:0
// CRL Distribution Points must have tag 0
// Issuer Alternative Name must be of type rfc822Name or a URI (tag 1 and tag 6)

// -- 18013-5 IACA SPECIFIC LEAF EXTENSION VALUE CHECKS -- //
// Extended Key Usage: 1.0.18013.5.1.2
// Key Usage: 0 (digitalSignature)
// CRL Distribution Points must have tag 0
// Issuer Alternative Name must be of type rfc822Name or a URI (tag 1 and tag 6)

/*  All the checks in this file relate to requirements for IACA x509 certificates as
detailed in Annex B of ISO18013-5. Specifically, the requirements for values in
root and signer certificates are given in tables B.2 and B.4 */
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

    let root_crit_extensions: Vec<&Extension> =
        root_extensions.iter().filter(|ext| ext.critical).collect();

    //TODO: check for any critical extensions beyond what is expected

    // Key Usage 2.5.29.15
    if let Some(key_usage) = root_crit_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_KEY_USAGE)
    {
        x509_errors.append(&mut validate_root_key_usage(
            key_usage.extn_value.as_bytes().to_vec(),
        ));
    } else {
        x509_errors.push(Error::ValidationError(
            "The root certificate is expected to have its key usage limited to keyCertSign and crlSign, but no restrictions were specified".to_string(),
        ));
    };

    // Basic Constraints 2.5.29.19
    if let Some(basic_constraints) = root_crit_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_BASIC_CONSTRAINTS)
    {
        x509_errors.append(&mut validate_basic_constraints(
            basic_constraints.extn_value.as_bytes().to_vec(),
        ));
    } else {
        x509_errors.push(Error::ValidationError(
            "The root certificate is expected to have critical basic constraints specificied, but the extensions was not found".to_string()
        ));
    };

    //CRL Distribution Points  2.5.29.31
    if let Some(crl_distribution_point) = root_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_CRL_DISTRIBUTION_POINTS)
    {
        x509_errors.append(&mut validate_crl_distribution_point(
            crl_distribution_point.extn_value.as_bytes().to_vec(),
        ));
    } else {
        x509_errors.push(Error::ValidationError("The root certificate is expected to have a crl distribution point specificied, but the extensions was not found".to_string()));
    };

    // Issuer Alternative Name  2.5.29.18
    if let Some(issuer_alternative_name) = root_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_ISSUER_ALTERNATIVE_NAME)
    {
        x509_errors.append(&mut validate_issuer_alternative_name(
            issuer_alternative_name.extn_value.as_bytes().to_vec(),
        ));
    } else {
        x509_errors.push(Error::ValidationError(
            "The root certificate is expected to have issuer alternative name specificied, but the extensions was not found".to_string()
        ));
    };

    x509_errors
}

pub fn validate_iaca_signer_extensions(leaf_extensions: Vec<Extension>, value_extended_key_usage: &str) -> Vec<Error> {
    let disallowed = iaca_disallowed_x509_extensions();
    let mut x509_errors: Vec<Error> = vec![];
    let mut errors: Vec<Error> = vec![];
    for extension in leaf_extensions.clone() {
        if let Some(disallowed_extension) = disallowed
            .iter()
            .find(|oid| extension.extn_id.to_string() == **oid)
        {
            errors.push(Error::ValidationError(format!(
                "The extension with oid: {:?} is not allowed in the IACA certificate profile",
                disallowed_extension
            )));
        }
    }

    let leaf_crit_extensions: Vec<&Extension> =
        leaf_extensions.iter().filter(|ext| ext.critical).collect();

    // Key Usage 2.5.29.15
    if let Some(key_usage) = leaf_crit_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_KEY_USAGE)
    {
        x509_errors.append(&mut validate_signer_key_usage(
            key_usage.extn_value.as_bytes().to_vec(),
        ));
    } else {
        x509_errors.push(Error::ValidationError(
            "Missing critical KeyUsage extension in the signer certificate".to_string(),
        ));
    }

    // Extended Key Usage     2.5.29.37
    if let Some(extended_key_usage) = leaf_crit_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == OID_EXTENDED_KEY_USAGE)
    {
        x509_errors.append(&mut validate_extended_key_usage(
            extended_key_usage.extn_value.as_bytes().to_vec(),
            value_extended_key_usage
        ));
    } else {
        x509_errors.push(Error::ValidationError(
            "Missing critical ExtendedKeyUsage extension in the signer certificate".to_string(),
        ));
    };

    //CRL Distribution Points  2.5.29.31
    if let Some(crl_distribution_point) = leaf_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_CRL_DISTRIBUTION_POINTS)
    {
        x509_errors.append(&mut validate_crl_distribution_point(
            crl_distribution_point.extn_value.as_bytes().to_vec(),
        ));
    } else {
        x509_errors.push(Error::ValidationError(
            "The leaf certificate is expected to have a crl distribution point specificied, but the extensions was not found".to_string(),
        ));
    };

    // Issuer Alternative Name  2.5.29.18
    if let Some(issuer_alternative_name) = leaf_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_ISSUER_ALTERNATIVE_NAME)
    {
        x509_errors.append(&mut validate_issuer_alternative_name(
            issuer_alternative_name.extn_value.as_bytes().to_vec(),
        ));
    } else {
        x509_errors.push(Error::ValidationError("The leaf certificate is expected to have issuer alternative name specificied, but the extensions was not found".to_string()));
    };

    x509_errors
}

/*  A signer certificate should have digital signatures set for it's key usage,
but not other key usages are allowed */
pub fn validate_signer_key_usage(bytes: Vec<u8>) -> Vec<Error> {
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

/*  A root certificate should have KeyCertSign and CRLSign set for key usage,
but no other key usages are allowed */
pub fn validate_root_key_usage(bytes: Vec<u8>) -> Vec<Error> {
    let mut errors = vec![];
    let key_usage = KeyUsage::from_der(&bytes);
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

/*  Extended key usage in the signer certificate should be set to this OID meant specifically for mDL signing.
Note that this value will be different for other types of mdocs  */

pub fn validate_extended_key_usage(bytes: Vec<u8>, value_extended_key_usage: &str) -> Vec<Error> {
    let extended_key_usage = ExtendedKeyUsage::from_der(&bytes);
    match extended_key_usage {
        Ok(eku) => {
            if !eku
                .0
                .into_iter()
                .any(|oid| oid.to_string() == value_extended_key_usage)
            {
                return vec![Error::ValidationError(
                    "Invalid extended key usage, expected: 1.0.18013.5.1.2".to_string(),
                )];
            };
            vec![]
        }
        Err(e) => {
            vec![Error::DecodingError(e.to_string())]
        }
    }
}

/*  The CRL DistributionPoint shall not contain values for crl_issuer and reasons.
Every Distribution Point must be of a type URI or RFC822Name */
pub fn validate_crl_distribution_point(bytes: Vec<u8>) -> Vec<Error> {
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

/*  The Issuer Alternative Name must be of a type URI or RFC822Name */
pub fn validate_issuer_alternative_name(bytes: Vec<u8>) -> Vec<Error> {
    let iss_altname = IssuerAltName::from_der(&bytes);
    match iss_altname {
        Ok(ian) => check_general_name_types(ian.0),
        Err(e) => {
            vec![Error::DecodingError(e.to_string())]
        }
    }
}

/*  Basic Constraints must be CA: true, path_len: 0 */
pub fn validate_basic_constraints(bytes: Vec<u8>) -> Vec<Error> {
    let basic_constraints = BasicConstraints::from_der(&bytes);
    match basic_constraints {
        Ok(bc) => {
            if !bc.path_len_constraint.is_some_and(|path_len| path_len == 0) && bc.ca {
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

pub fn iaca_disallowed_x509_extensions() -> Vec<String> {
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
