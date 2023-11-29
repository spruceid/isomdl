use crate::definitions::x509::error::Error as X509Error;
use crate::definitions::x509::extensions::{
    validate_iaca_root_extensions, validate_iaca_signer_extensions,
};
use crate::definitions::x509::x5chain::X509;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::CertificateInner;
use x509_cert::der::Decode;

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

pub fn process_validation_outcomes(
    leaf_certificate: CertificateInner,
    root_certificate: CertificateInner,
    rule_set: ValidationRuleSet,
) -> Vec<X509Error> {
    let mut errors: Vec<X509Error> = vec![];

    //execute checks on x509 components
    match apply_ruleset(leaf_certificate, root_certificate.clone(), rule_set) {
        Ok(mut v) => {
            errors.append(&mut v);
        }
        Err(e) => {
            errors.push(e);
        }
    }

    // make sure that the trust anchor is still valid
    errors.append(&mut check_validity_period(&root_certificate));

    //TODO: check CRL to make sure the certificates have not been revoked
    errors
}

pub fn validate_with_ruleset(
    leaf_certificate: CertificateInner,
    trust_anchor: TrustAnchor,
) -> Vec<X509Error> {
    let mut errors: Vec<X509Error> = vec![];

    match trust_anchor {
        TrustAnchor::Iaca(certificate) => {
            let rule_set = ValidationRuleSet {
                distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
                typ: RuleSetType::IACA,
            };
            match x509_cert::Certificate::from_der(&certificate.bytes) {
                Ok(root_certificate) => {
                    errors.append(&mut process_validation_outcomes(
                        leaf_certificate,
                        root_certificate,
                        rule_set,
                    ));
                }
                Err(e) => {
                    errors.push(e.into());
                }
            };
        }
        TrustAnchor::Aamva(certificate) => {
            let rule_set = ValidationRuleSet {
                distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
                typ: RuleSetType::AAMVA,
            };
            //The Aamva ruleset follows the IACA ruleset, but makes the ST value mandatory
            match x509_cert::Certificate::from_der(&certificate.bytes) {
                Ok(root_certificate) => {
                    errors.append(&mut process_validation_outcomes(
                        leaf_certificate,
                        root_certificate,
                        rule_set,
                    ));
                }
                Err(e) => {
                    errors.push(e.into());
                }
            };
        }
        TrustAnchor::Custom(_certificate, _ruleset) => {
            //TODO
        }
    }
    errors
}

pub fn validate_with_trust_anchor(leaf_x509: X509, trust_anchor: TrustAnchor) -> Vec<X509Error> {
    let mut errors: Vec<X509Error> = vec![];
    let leaf_certificate = x509_cert::Certificate::from_der(&leaf_x509.bytes);

    match leaf_certificate {
        Ok(leaf) => {
            errors.append(&mut validate_with_ruleset(leaf, trust_anchor));
        }
        Err(e) => errors.push(e.into()),
    }
    errors
}

pub fn check_validity_period(certificate: &CertificateInner) -> Vec<X509Error> {
    let validity = certificate.tbs_certificate.validity;
    let mut errors: Vec<X509Error> = vec![];
    if validity.not_after.to_unix_duration().as_secs()
        < OffsetDateTime::now_utc().unix_timestamp() as u64
    {
        errors.push(X509Error::ValidationError(format!(
            "Expired certificate with subject: {:?}",
            certificate.tbs_certificate.subject
        )));
    };
    if validity.not_before.to_unix_duration().as_secs()
        > OffsetDateTime::now_utc().unix_timestamp() as u64
    {
        errors.push(X509Error::ValidationError(format!(
            "Not yet valid certificate with subject: {:?}",
            certificate.tbs_certificate.subject
        )));
    };

    errors
}

/* Validates:

- all the correct distinghuished names are present
and match the
- all the correct extensions are present
- the extensions are set to the ruleset values
-  */
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

    // if all the needed distinguished names have been collected,
    // there should be the same number of names collected as are present in the ruleset
    if root_distinguished_names.len() != rule_set.distinguished_names.len() {
        errors.push(X509Error::ValidationError("The congifured validation ruleset requires a distinguished name that is not found in the submitted root certificate".to_string()));
    }

    if leaf_distinguished_names.len() != rule_set.distinguished_names.len() {
        errors.push(X509Error::ValidationError("The congifured validation ruleset requires a distinguished name that is not found in the submitted signer certificate".to_string()));
    }

    let Some(root_extensions) = root_certificate.tbs_certificate.extensions else {
        return Err(X509Error::ValidationError(
            "The root certificate is expected to have extensions, but none were found. Skipping all following extension validation checks..".to_string(),
        ));
    };

    let Some(leaf_extensions) = leaf_certificate.tbs_certificate.extensions else {
        return Err(X509Error::ValidationError(
            "The signer certificate is expected to have extensions, but none were found. Skipping all following extension validation checks.. "
                .to_string(),
        ));
    };

    match rule_set.typ {
        //Under the IACA ruleset, the values for S or ST should be the same in subject and issuer if they are present in both
        RuleSetType::IACA => {
            let mut extension_errors = validate_iaca_root_extensions(root_extensions);
            extension_errors.append(&mut validate_iaca_signer_extensions(leaf_extensions));
            for dn in leaf_distinguished_names {
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
            Ok(extension_errors)
        }
        //Under the AAMVA ruleset, S/ST is mandatory and should be the same in the subject and issuer
        RuleSetType::AAMVA => {
            let mut extension_errors = validate_iaca_root_extensions(root_extensions);
            extension_errors.append(&mut validate_iaca_signer_extensions(leaf_extensions));
            for dn in leaf_distinguished_names {
                let Some(_root_dn) = root_distinguished_names.iter().find(|r| r == &&dn) else {
                    return Err(X509Error::ValidationError(format!("Mismatch between supplied certificate issuer attribute: {:?} and the trust anchor registry.", dn.value)));
                };
            }
            Ok(extension_errors)
        }
        RuleSetType::Custom => {
            //TODO
            Err(X509Error::ValidationError(
                "Unimplemented ruleset".to_string(),
            ))
        }
        RuleSetType::ReaderAuth => {
            //TODO
            Err(X509Error::ValidationError(
                "Unimplemented ruleset".to_string(),
            ))
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
