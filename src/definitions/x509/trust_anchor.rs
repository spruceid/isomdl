use crate::definitions::x509::x5chain::{check_signature, X509};
use crate::presentation::reader::Error;
use asn1_rs::{Any, BitString, FromDer, Oid, SequenceOf};
use serde::{Deserialize, Serialize};
use x509_cert::ext::pkix::KeyUsage;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::{CertificateInner, Rfc5280};
use x509_cert::ext::Extension;
use x509_cert::{der::Decode, Certificate};
use crate::definitions::x509::extensions::{
    validate_basic_constraints,
    validate_crl_distribution_point,
    validate_extended_key_usage,
    validate_issuer_alternative_name,
    validate_signer_key_usage,
    validate_root_key_usage,
    validate_iaca_root_extensions,
    validate_iaca_signer_extensions,
    iaca_disallowed_x509_extensions
};
use crate::definitions::x509::error::Error as X509Error;


// -- DISTINGUISHED NAMES AND OID OVERVIEW -- //
// CN	                commonName	                    2.5.4.3
// SN	                surname 	                    2.5.4.4
// SERIALNUMBER	        serialNumber 	                2.5.4.5
// C	                countryName 	                2.5.4.6
// L	                localityName 	                2.5.4.7
// ST or S	            stateOrProvinceName 	        2.5.4.8
// STREET	            streetAddress 	                2.5.4.9
// O	                organizationName 	            2.5.4.10
// OU	                organizationalUnit 	            2.5.4.11
// T or TITLE	        title 	                        2.5.4.12
// G or GN	            givenName 	                    2.5.4.42
// initials	            initials 	                    2.5.4.43
// generationQualifier	generation qualifier	        2.5.4.44
// dnQualifier	        distinguished name qualifier 	2.5.4.46
// pseudonym	        pseudonym 	                    2.5.4.65

// -- IACA/AAMVA DISALLOWED EXTENSION OIDs -- //
//  Policy Mappings         2.5.29.33
//  NameConstraints         2.5.29.30
//  PolicyConstraints       2.5.29.36
//  InhibitAnyPolicy        2.5.29.54
//  FreshestCRL             2.5.29.46

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
//

const EXTENDED_KEY_USAGE: &str = "1.0.18013.5.1.2";
const ROOT_KEY_USAGE: [usize; 2] = [5, 6];
const LEAF_KEY_USAGE: [usize; 1] = [0];
const BASIC_CONSTRAINTS: [u32; 1] = [0];
const CRL_DISTRIBUTION_POINT: [u32; 1] = [0];
const ISSUER_ALTERNATIVE_NAME: [u32; 2] = [1, 6];

#[derive(Serialize, Deserialize, Clone)]
pub enum TrustAnchor {
    Iaca(X509),
    Aamva(X509),
    Custom(X509, ValidationRuleSet),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ValidationRuleSet {
    pub distinguished_names: Vec<String>,
    #[serde(rename = "type")]
    pub typ: RuleSetType,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum RuleSetType {
    IACA,
    AAMVA,
    Custom,
    ReaderAuth,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TrustAnchorRegistry {
    pub certificates: Vec<TrustAnchor>,
}

pub fn iaca_root_extension_rules() -> BTreeMap<String, Vec<usize>> {
    BTreeMap::from([
        ("2.5.29.15".to_string(), vec![5, 6]),
        ("2.5.29.19".to_string(), vec![0]),
        ("2.5.29.18".to_string(), vec![1, 6]),
        ("2.5.29.37".to_string(), vec![0]),
    ])
}

pub fn process_validation_outcomes(leaf_certificate: CertificateInner, root_certificate: CertificateInner ) -> Vec<X509Error> {
    let mut errors: Vec<X509Error> = vec![];
    let rule_set = ValidationRuleSet {
        distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
        typ: RuleSetType::IACA,
    };

    let validation = apply_ruleset(
        leaf_certificate,
        root_certificate.clone(),
        rule_set,
    );
    match validation {
        Ok(mut v) => {
            errors.append(&mut v);
        },
        Err(e) => {
            errors.push(e);
        }
    }

    let validity = check_validity_period(&root_certificate);
    match validity {
        Ok(v)=> {
        },
        Err(e) => {
            errors.push(e);
        }
    }
    errors
}

pub fn helper_with_ruleset(leaf_certificate: CertificateInner, trust_anchor: TrustAnchor )-> Vec<X509Error> {
    let mut errors: Vec<X509Error> = vec![];

    match trust_anchor {
        //TODO: AAMVA TrustAnchor rules
        TrustAnchor::Iaca(certificate) => {
            // 18013-5 specifies checks that shall be performed for IACA certificates

            match x509_cert::Certificate::from_der(&certificate.bytes) {
                Ok(root_certificate) => {
                    errors.append(&mut process_validation_outcomes(leaf_certificate, root_certificate));
                },
                Err(e) => {
                    errors.push(e.into());
                }
            };
            
        }
        TrustAnchor::Aamva(certificate) => {
            //The Aamva ruleset follows the IACA ruleset, but makes the ST value mandatory
            match x509_cert::Certificate::from_der(&certificate.bytes) {
                Ok(root_certificate) => {
                    errors.append(&mut process_validation_outcomes(leaf_certificate, root_certificate));
                },
                Err(e) => {
                    errors.push(e.into());
                }
            };
        }
        TrustAnchor::Custom(certificate, _ruleset) => {
            //TODO
        }
    }
    errors
}

pub fn validate_with_trust_anchor(
    leaf_x509: X509,
    trust_anchor: TrustAnchor,
) -> Vec<X509Error>{
    let mut errors: Vec<X509Error> = vec![];
    let leaf_certificate = x509_cert::Certificate::from_der(&leaf_x509.bytes);

    match leaf_certificate{
        Ok(leaf) => {
            errors.append(&mut helper_with_ruleset(leaf, trust_anchor));
        }, 
        Err(e)=> {
            errors.push(e.into())
        }
    }
    errors
}

pub fn check_validity_period(certificate: &CertificateInner) -> Result<(), X509Error> {
    let validity = certificate.tbs_certificate.validity;
    if validity.not_after.to_unix_duration().as_secs()
        < OffsetDateTime::now_utc().unix_timestamp() as u64
    {
        return Err(X509Error::ValidationError(format!(
            "Expired certificate with subject: {:?}",
            certificate.tbs_certificate.subject
        )));
    };
    if validity.not_before.to_unix_duration().as_secs()
        > OffsetDateTime::now_utc().unix_timestamp() as u64
    {
        return Err(X509Error::ValidationError(format!(
            "Not yet valid certificate with subject: {:?}",
            certificate.tbs_certificate.subject
        )));
    };

    Ok(())
}

fn apply_ruleset(
    leaf_certificate: CertificateInner,
    root_certificate: CertificateInner,
    rule_set: ValidationRuleSet,
) -> Result<Vec<X509Error>, X509Error> {
    let mut errors: Vec<X509Error> = vec![];
    // collect all the distinguished names in the root certificate that the validation ruleset requires
    let root_distinguished_names: Vec<AttributeTypeAndValue> = root_certificate
        .tbs_certificate
        .subject
        .0
        .into_iter()
        .map(|rdn| {
            rdn.0
                .into_vec()
                .into_iter()
                .filter(|atv| {
                    rule_set
                        .distinguished_names
                        .iter()
                        .any(|oid| oid == &atv.oid.to_string())
                })
                .collect::<Vec<AttributeTypeAndValue>>()
        })
        .collect::<Vec<Vec<AttributeTypeAndValue>>>()
        .into_iter()
        .flatten()
        .collect();

    // collect all the distinguished names in the signer certificate that the validation ruleset requires
    let leaf_distinguished_names: Vec<AttributeTypeAndValue> = leaf_certificate
        .tbs_certificate
        .issuer
        .0
        .into_iter()
        .map(|r| {
            r.0.into_vec()
                .into_iter()
                .filter(|atv| {
                    rule_set
                        .distinguished_names
                        .iter()
                        .any(|oid| oid == &atv.oid.to_string())
                })
                .collect::<Vec<AttributeTypeAndValue>>()
        })
        .collect::<Vec<Vec<AttributeTypeAndValue>>>()
        .into_iter()
        .flatten()
        .collect();

    // fix this
    if root_distinguished_names.len() != rule_set.distinguished_names.len() {
        errors.push(X509Error::ValidationError("The congifured validation ruleset requires a distinguished name that is not found in the submitted root certificate".to_string()));
    }

    if leaf_distinguished_names.len() != rule_set.distinguished_names.len() {
        errors.push(X509Error::ValidationError("The congifured validation ruleset requires a distinguished name that is not found in the submitted signer certificate".to_string()));
    }

    let Some(root_extensions) = root_certificate.tbs_certificate.extensions else {
        return Err(X509Error::ValidationError(
            "The root certificate is expected to have extensions, but none were found".to_string(),
        ));
    };

    let Some(leaf_extensions) = leaf_certificate.tbs_certificate.extensions else {
        return Err(X509Error::ValidationError(
            "The signer certificate is expected to have extensions, but none were found"
                .to_string(),
        ));
    };

    match rule_set.typ {
        RuleSetType::IACA => {
            let mut root_extension_errors = validate_iaca_root_extensions(root_extensions)?;
            let mut signer_extension_errors = validate_iaca_signer_extensions(leaf_extensions)?;
            root_extension_errors.append(&mut signer_extension_errors);
            for dn in leaf_distinguished_names {
                let disallowed = iaca_disallowed_x509_extensions();
                if let Some(disallowed_extension) =
                    disallowed.iter().find(|oid| dn.oid.to_string() == **oid)
                {
                    return Err(X509Error::ValidationError(format!("The extension with oid: {:?} is not allowed in the IACA certificate profile", disallowed_extension)));
                }

                //Under the IACA ruleset, the values for S or ST should be the same in subject and issuer if they are present in both
                if dn.oid.to_string() == *"2.5.4.8" {
                    let state_or_province =
                        root_distinguished_names.iter().find(|r| r.oid == dn.oid);
                    if let Some(st_or_s) = state_or_province {
                        if dn != *st_or_s {
                            return Err(X509Error::ValidationError(format!("Mismatch between supplied certificate issuer attribute: {:?} and the trust anchor registry.", dn)));
                        }
                    }
                } else {
                    let Some(_root_dn) = root_distinguished_names.iter().find(|r| r == &&dn) else {
                        return Err(X509Error::ValidationError(format!("Mismatch between supplied certificate issuer attribute: {:?} and the trust anchor registry.", dn.value)));
                    };
                }
            }
            Ok(root_extension_errors)
        }
        RuleSetType::AAMVA => {
            let mut root_extension_errors = validate_iaca_root_extensions(root_extensions)?;
            let mut signer_extension_errors = validate_iaca_signer_extensions(leaf_extensions)?;
            root_extension_errors.append(&mut signer_extension_errors);
            for dn in leaf_distinguished_names {
                let disallowed = iaca_disallowed_x509_extensions();
                if let Some(disallowed_extension) =
                    disallowed.iter().find(|oid| dn.oid.to_string() == **oid)
                {
                    return Err(X509Error::ValidationError(format!("The extension with oid: {:?} is not allowed in the IACA certificate profile", disallowed_extension)));
                }

                let Some(_root_dn) = root_distinguished_names.iter().find(|r| r == &&dn) else {
                    return Err(X509Error::ValidationError(format!("Mismatch between supplied certificate issuer attribute: {:?} and the trust anchor registry.", dn.value)));
                };
            }
            Ok(root_extension_errors)
        }
        RuleSetType::Custom => {
            //TODO
            Err(X509Error::ValidationError("Unimplemented ruleset".to_string()))
        }
        RuleSetType::ReaderAuth => {
            //TODO
            Err(X509Error::ValidationError("Unimplemented ruleset".to_string()))
        }
    }
}

pub fn find_anchor(
    leaf_certificate: CertificateInner,
    trust_anchor_registry: Option<TrustAnchorRegistry>,
    ) -> Result<Option<TrustAnchor>, X509Error> {
    let leaf_issuer = leaf_certificate.tbs_certificate.issuer;

    let Some(root_certificates) = trust_anchor_registry else {
        return Ok(None);
    };
    let Some(trust_anchor) = root_certificates
        .certificates
        .into_iter()
        .find(|trust_anchor| match trust_anchor {
            TrustAnchor::Iaca(certificate) => {
                match x509_cert::Certificate::from_der(&certificate.bytes) {
                    Ok(root_cert) => root_cert.tbs_certificate.subject == leaf_issuer,
                    Err(_) => false,
                }
            }
            TrustAnchor::Custom(certificate, _ruleset) => {
                match x509_cert::Certificate::from_der(&certificate.bytes) {
                    Ok(root_cert) => root_cert.tbs_certificate.subject == leaf_issuer,
                    Err(_) => false,
                }
            }
            TrustAnchor::Aamva(certificate) => {
                match x509_cert::Certificate::from_der(&certificate.bytes) {
                    Ok(root_cert) => root_cert.tbs_certificate.subject == leaf_issuer,
                    Err(_) => false,
                }
            }
        })
    else {
        return Err(X509Error::ValidationError(
            "The certificate issuer does not match any known trusted issuer".to_string(),
        ));
    };
    Ok(Some(trust_anchor))
}