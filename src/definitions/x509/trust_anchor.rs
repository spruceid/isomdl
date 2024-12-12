use crate::definitions::x509::{
    error::Error as X509Error,
    extensions::{validate_iaca_root_extensions, validate_iaca_signer_extensions},
};
use anyhow::Error;
use const_oid::ObjectIdentifier;
use der::{DecodePem, EncodePem};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use x509_cert::{attr::AttributeTypeAndValue, Certificate};

#[derive(Debug, Clone)]
pub enum TrustAnchor {
    Iaca(Certificate),
    Aamva(Certificate),
    IacaReader(Certificate),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PemTrustAnchor {
    Iaca(String),
    Aamva(String),
    IacaReader(String),
}

impl<'l> TryFrom<&'l TrustAnchor> for PemTrustAnchor {
    type Error = Error;

    fn try_from(value: &'l TrustAnchor) -> Result<Self, Self::Error> {
        Ok(match value {
            TrustAnchor::Iaca(c) => PemTrustAnchor::Iaca(c.to_pem(Default::default())?),
            TrustAnchor::Aamva(c) => PemTrustAnchor::Aamva(c.to_pem(Default::default())?),
            TrustAnchor::IacaReader(c) => PemTrustAnchor::IacaReader(c.to_pem(Default::default())?),
        })
    }
}

impl TryFrom<PemTrustAnchor> for TrustAnchor {
    type Error = Error;

    fn try_from(value: PemTrustAnchor) -> Result<Self, Self::Error> {
        Ok(match value {
            PemTrustAnchor::Iaca(c) => TrustAnchor::Iaca(Certificate::from_pem(&c)?),
            PemTrustAnchor::Aamva(c) => TrustAnchor::Aamva(Certificate::from_pem(&c)?),
            PemTrustAnchor::IacaReader(c) => TrustAnchor::IacaReader(Certificate::from_pem(&c)?),
        })
    }
}

impl Serialize for TrustAnchor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;

        PemTrustAnchor::try_from(self)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TrustAnchor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        PemTrustAnchor::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
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
    NamesOnly,
    ReaderAuth,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TrustAnchorRegistry {
    pub certificates: Vec<TrustAnchor>,
}

impl TrustAnchorRegistry {
    pub fn from_pem_iaca_certificates(certs: Vec<String>) -> Result<Self, Error> {
        Ok(Self {
            certificates: certs
                .into_iter()
                .map(PemTrustAnchor::Iaca)
                .map(TrustAnchor::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

fn process_validation_outcomes(
    leaf_certificate: &Certificate,
    root_certificate: &Certificate,
    rule_set: ValidationRuleSet,
) -> Vec<X509Error> {
    let mut errors: Vec<X509Error> = vec![];

    //execute checks on x509 components
    match apply_ruleset(leaf_certificate, root_certificate, rule_set) {
        Ok(mut v) => {
            errors.append(&mut v);
        }
        Err(e) => {
            errors.push(e);
        }
    }

    // make sure that the trust anchor is still valid
    errors.append(&mut check_validity_period(root_certificate));

    //TODO: check CRL to make sure the certificates have not been revoked
    errors
}

pub fn validate_with_ruleset(
    leaf_certificate: &Certificate,
    trust_anchor: &TrustAnchor,
) -> Vec<X509Error> {
    let mut errors: Vec<X509Error> = vec![];

    match trust_anchor {
        TrustAnchor::Iaca(root_certificate) => {
            let rule_set = ValidationRuleSet {
                distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
                typ: RuleSetType::IACA,
            };
            errors.append(&mut process_validation_outcomes(
                leaf_certificate,
                root_certificate,
                rule_set,
            ));
        }
        TrustAnchor::Aamva(root_certificate) => {
            let rule_set = ValidationRuleSet {
                distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
                typ: RuleSetType::AAMVA,
            };
            errors.append(&mut process_validation_outcomes(
                leaf_certificate,
                root_certificate,
                rule_set,
            ));
        }
        TrustAnchor::IacaReader(root_certificate) => {
            let rule_set = ValidationRuleSet {
                distinguished_names: vec!["2.5.4.3".to_string()],
                typ: RuleSetType::ReaderAuth,
            };
            errors.append(&mut process_validation_outcomes(
                leaf_certificate,
                root_certificate,
                rule_set,
            ));
        }
    }
    errors
}

pub fn check_validity_period(certificate: &Certificate) -> Vec<X509Error> {
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
    leaf_certificate: &Certificate,
    root_certificate: &Certificate,
    rule_set: ValidationRuleSet,
) -> Result<Vec<X509Error>, X509Error> {
    let mut errors: Vec<X509Error> = vec![];
    // collect all the distinguished names in the root certificate that the validation ruleset requires
    let root_distinguished_names: Vec<&AttributeTypeAndValue> = root_certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| {
            rdn.0.as_slice().iter().filter(|atv| {
                rule_set
                    .distinguished_names
                    .iter()
                    .any(|oid| oid == &atv.oid.to_string())
            })
        })
        .collect();

    // collect all the distinguished names in the signer certificate that the validation ruleset requires
    let leaf_distinguished_names: Vec<&AttributeTypeAndValue> = leaf_certificate
        .tbs_certificate
        .issuer
        .0
        .iter()
        .flat_map(|rdn| {
            rdn.0.as_slice().iter().filter(|atv| {
                rule_set
                    .distinguished_names
                    .iter()
                    .any(|oid| oid == &atv.oid.to_string())
            })
        })
        .collect();

    // if all the needed distinguished names have been collected,
    // there should be the same number of names collected as are present in the ruleset
    if root_distinguished_names.len() != rule_set.distinguished_names.len() {
        errors.push(X509Error::ValidationError("The configured validation ruleset requires a distinguished name that is not found in the submitted root certificate".to_string()));
    }

    if leaf_distinguished_names.len() != rule_set.distinguished_names.len() {
        errors.push(X509Error::ValidationError("The configured validation ruleset requires a distinguished name that is not found in the submitted signer certificate".to_string()));
    }

    let Some(root_extensions) = root_certificate.tbs_certificate.extensions.as_ref() else {
        return Err(X509Error::ValidationError(
            "The root certificate is expected to have extensions, but none were found. Skipping all following extension validation checks..".to_string(),
        ));
    };

    let Some(leaf_extensions) = leaf_certificate.tbs_certificate.extensions.as_ref() else {
        return Err(X509Error::ValidationError(
            "The signer certificate is expected to have extensions, but none were found. Skipping all following extension validation checks.. "
                .to_string(),
        ));
    };

    match rule_set.typ {
        //Under the IACA ruleset, the values for S or ST should be the same in subject and issuer if they are present in both
        RuleSetType::IACA => {
            let mut extension_errors = validate_iaca_root_extensions(root_extensions);
            extension_errors.append(&mut validate_iaca_signer_extensions(
                leaf_extensions,
                mdoc_extended_key_usage_oid(),
            ));
            for dn in leaf_distinguished_names {
                if dn.oid == const_oid::db::rfc2256::STATE_OR_PROVINCE_NAME {
                    if let Some(&root_state_or_province) =
                        root_distinguished_names.iter().find(|r| r.oid == dn.oid)
                    {
                        if dn != root_state_or_province {
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
            extension_errors.append(&mut validate_iaca_signer_extensions(
                leaf_extensions,
                mdoc_extended_key_usage_oid(),
            ));
            for dn in leaf_distinguished_names {
                let Some(_root_dn) = root_distinguished_names.iter().find(|r| r == &&dn) else {
                    return Err(X509Error::ValidationError(format!("Mismatch between supplied certificate issuer attribute: {:?} and the trust anchor registry.", dn.value)));
                };
            }
            Ok(extension_errors)
        }
        RuleSetType::NamesOnly => {
            for dn in leaf_distinguished_names {
                let Some(_root_dn) = root_distinguished_names.iter().find(|r| r == &&dn) else {
                    return Err(X509Error::ValidationError(format!("Mismatch between supplied certificate issuer attribute: {:?} and the trust anchor registry.", dn.value)));
                };
            }
            Ok(vec![])
        }
        RuleSetType::ReaderAuth => Ok(validate_iaca_signer_extensions(
            leaf_extensions,
            reader_extended_key_usage_oid(),
        )),
    }
}

pub fn find_anchor<'l>(
    leaf_certificate: &Certificate,
    trust_anchor_registry: Option<&'l TrustAnchorRegistry>,
) -> Result<Option<&'l TrustAnchor>, X509Error> {
    let leaf_issuer = &leaf_certificate.tbs_certificate.issuer;

    let Some(root_certificates) = trust_anchor_registry else {
        return Ok(None);
    };
    let Some(trust_anchor) =
        root_certificates
            .certificates
            .iter()
            .find(|trust_anchor| match trust_anchor {
                TrustAnchor::Iaca(certificate)
                | TrustAnchor::Aamva(certificate)
                | TrustAnchor::IacaReader(certificate) => {
                    &certificate.tbs_certificate.subject == leaf_issuer
                }
            })
    else {
        return Err(X509Error::ValidationError(
            "The certificate issuer does not match any known trusted issuer".to_string(),
        ));
    };
    Ok(Some(trust_anchor))
}

fn mdoc_extended_key_usage_oid() -> ObjectIdentifier {
    // Unwrap safety: unit tested.
    ObjectIdentifier::new("1.0.18013.5.1.2").unwrap()
}

fn reader_extended_key_usage_oid() -> ObjectIdentifier {
    // Unwrap safety: unit tested.
    ObjectIdentifier::new("1.0.18013.5.1.6").unwrap()
}

#[cfg(test)]
mod test {
    #[test]
    fn mdoc_extended_key_usage_oid_doesnt_panic() {
        super::mdoc_extended_key_usage_oid();
    }

    #[test]
    fn reader_extended_key_usage_oid_doesnt_panic() {
        super::reader_extended_key_usage_oid();
    }
}
