use crate::issuance::x5chain::{check_signature, X509};
use crate::presentation::reader::Error;
use asn1_rs::{Any, BitString, FromDer, Oid, SequenceOf};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::CertificateInner;
use x509_cert::ext::Extension;
use x509_cert::{der::Decode, Certificate};
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

fn iaca_disallowed_x509_extensions() -> Vec<String> {
    vec![
        "2.5.29.30".to_string(),
        "2.5.29.33".to_string(),
        "2.5.29.36".to_string(),
        "2.5.29.46".to_string(),
        "2.5.29.54".to_string(),
    ]
}

pub fn iaca_root_extension_rules() -> BTreeMap<String, Vec<usize>> {
    BTreeMap::from([
        ("2.5.29.15".to_string(), vec![5, 6]),
        ("2.5.29.19".to_string(), vec![0]),
        ("2.5.29.18".to_string(), vec![1, 6]),
        ("2.5.29.37".to_string(), vec![0]),
    ])
}

pub fn validate_with_trust_anchor(
    leaf_x509: X509,
    trust_anchor: TrustAnchor,
) -> Result<Vec<Error>, Error> {
    let leaf_certificate = x509_cert::Certificate::from_der(&leaf_x509.bytes)?;
    let mut results: Vec<Error> = vec![];
    match trust_anchor {
        //TODO: AAMVA TrustAnchor rules
        TrustAnchor::Iaca(certificate) => {
            // 18013-5 specifies checks that shall be performed for IACA certificates
            let rule_set = ValidationRuleSet {
                distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
                typ: RuleSetType::IACA,
            };

            let root_certificate = x509_cert::Certificate::from_der(&certificate.bytes)?;
            results.append(&mut apply_ruleset(
                leaf_certificate,
                root_certificate.clone(),
                rule_set,
            )?);
            check_validity_period(&root_certificate)?;
            check_signature(&leaf_x509, &certificate)?;
            Ok(results)
        }
        TrustAnchor::Aamva(certificate) => {
            //The Aamva ruleset follows the IACA ruleset, but makes the ST value mandatory
            let rule_set = ValidationRuleSet {
                distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
                typ: RuleSetType::IACA,
            };
            let root_certificate = x509_cert::Certificate::from_der(&certificate.bytes)?;
            results.append(&mut apply_ruleset(
                leaf_certificate,
                root_certificate.clone(),
                rule_set,
            )?);
            check_validity_period(&root_certificate)?;
            check_signature(&leaf_x509, &certificate)?;
            Ok(results)
        }
        TrustAnchor::Custom(certificate, _ruleset) => {
            let _root_certificate = x509_cert::Certificate::from_der(&certificate.bytes)?;
            Ok(results)
        }
    }
}

pub fn check_validity_period(certificate: &Certificate) -> Result<(), Error> {
    let validity = certificate.tbs_certificate.validity;
    if validity.not_after.to_unix_duration().as_secs()
        < OffsetDateTime::now_utc().unix_timestamp() as u64
    {
        return Err(Error::MdocAuth(format!(
            "Expired certificate with subject: {:?}",
            certificate.tbs_certificate.subject
        )));
    };
    if validity.not_before.to_unix_duration().as_secs()
        > OffsetDateTime::now_utc().unix_timestamp() as u64
    {
        return Err(Error::MdocAuth(format!(
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
) -> Result<Vec<Error>, Error> {
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
        return Err(Error::MdocAuth("The congifured validation ruleset requires a distinguished name that is not found in the submitted root certificate".to_string()));
    }

    let Some(root_extensions) = root_certificate.tbs_certificate.extensions else {
        return Err(Error::MdocAuth(
            "The root certificate is expected to have extensions, but none were found".to_string(),
        ));
    };

    let Some(leaf_extensions) = leaf_certificate.tbs_certificate.extensions else {
        return Err(Error::MdocAuth(
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
                    return Err(Error::MdocAuth(format!("The extension with oid: {:?} is not allowed in the IACA certificate profile", disallowed_extension)));
                }

                //Under the IACA ruleset, the values for S or ST should be the same in subject and issuer if they are present in both
                if dn.oid.to_string() == *"2.5.4.8" {
                    let state_or_province =
                        root_distinguished_names.iter().find(|r| r.oid == dn.oid);
                    if let Some(st_or_s) = state_or_province {
                        if dn != *st_or_s {
                            return Err(Error::MdocAuth(format!("Mismatch between supplied certificate issuer attribute: {:?} and the trust anchor registry.", dn)));
                        }
                    }
                } else {
                    let Some(_root_dn) = root_distinguished_names.iter().find(|r| r == &&dn) else {
                        return Err(Error::MdocAuth(format!("Mismatch between supplied certificate issuer attribute: {:?} and the trust anchor registry.", dn.value)));
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
                    return Err(Error::MdocAuth(format!("The extension with oid: {:?} is not allowed in the IACA certificate profile", disallowed_extension)));
                }

                let Some(_root_dn) = root_distinguished_names.iter().find(|r| r == &&dn) else {
                    return Err(Error::MdocAuth(format!("Mismatch between supplied certificate issuer attribute: {:?} and the trust anchor registry.", dn.value)));
                };
            }
            Ok(root_extension_errors)
        }
        RuleSetType::Custom => {
            //TODO
            Err(Error::MdocAuth("Unimplemented ruleset".to_string()))
        }
        RuleSetType::ReaderAuth => {
            //TODO
            Err(Error::MdocAuth("Unimplemented ruleset".to_string()))
        }
    }
}

pub fn validate_iaca_root_extensions(root_extensions: Vec<Extension>) -> Result<Vec<Error>, Error> {
    let disallowed = iaca_disallowed_x509_extensions();
    let mut errors: Vec<Error> = vec![];
    for extension in root_extensions.clone() {
        if let Some(disallowed_extension) = disallowed
            .iter()
            .find(|oid| extension.extn_id.to_string() == **oid)
        {
            errors.push(Error::MdocAuth(format!(
                "The extension with oid: {:?} is not allowed in the IACA certificate profile",
                disallowed_extension
            )));
        }
    }

    let root_crit_extensions: Vec<&Extension> =
        root_extensions.iter().filter(|ext| ext.critical).collect();

    // Key Usage 2.5.29.15
    let Some(key_usage) = root_crit_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_KEY_USAGE)
    else {
        return Err(Error::MdocAuth(
            "The root certificate is expected to have its key usage limited to keyCertSign and crlSign, but no restrictions were specified".to_string(),
        ));
    };

    let decoded_key_usage_value: (_, BitString) =
        FromDer::from_der(key_usage.extn_value.as_bytes())
            .map_err(|e| Error::MdocAuth(e.to_string()))?;
    let Some(bitslice) = decoded_key_usage_value.1.as_bitslice() else {
        return Err(Error::MdocAuth(
            "Error decoding extension value as a bitslice".to_string(),
        ));
    };

    if bitslice.iter_ones().collect::<Vec<usize>>().as_slice() != ROOT_KEY_USAGE {
        errors.push(Error::MdocAuth(
            "the root certificate key usage extension is invalid".to_string(),
        ));
    }

    // Basic Constraints 2.5.29.19
    let Some(basic_constraints) = root_crit_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_BASIC_CONSTRAINTS)
    else {
        return Err(Error::MdocAuth(
            "The root certificate is expected to have critical basic constraints specificied, but the extensions was not found".to_string()
        ));
    };

    let decoded_basic_constraints: (_, SequenceOf<Any>) =
        FromDer::from_der(basic_constraints.extn_value.as_bytes())
            .map_err(|e| Error::MdocAuth(e.to_string()))?;
    let mut iter = decoded_basic_constraints.1.iter();
    let Some(ca) = iter.next() else {
        return Err(Error::MdocAuth(
            "The root certificate is expected to contain CA=true in the Basic Constraints, but found an empty sequence".to_string()
        ));
    };

    if !ca.as_boolean()?.bool() {
        errors.push(Error::MdocAuth(format!("The root certificate is expected to contain Basic Constraints CA=true, but found: {:?}", ca)));
    }
    let Some(path_len) = iter.next() else {
        return Err(Error::MdocAuth("The root certificate is expected to contain pathLen:0 in the Basic Constraints, but it was not found".to_string()));
    };

    if [path_len.as_integer()?.as_u32()?] != BASIC_CONSTRAINTS {
        errors.push(Error::MdocAuth(format!("The root certificate is expected to contain Basic Constraints pathLen=0, but found: {:?}", path_len)));
    }

    //CRL Distribution Points  2.5.29.31
    let Some(crl_distribution_point) = root_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_CRL_DISTRIBUTION_POINTS)
    else {
        return Err(Error::MdocAuth("The root certificate is expected to have a crl distribution point specificied, but the extensions was not found".to_string()));
    };

    let crl_dp: (_, SequenceOf<Any>) =
        FromDer::from_der(crl_distribution_point.extn_value.as_bytes())
            .map_err(|e| Error::MdocAuth(e.to_string()))?;
    let Some(distribution_points) = crl_dp.1.iter().next() else {
        return Err(Error::MdocAuth(
            "The root certificate is expected to have a crl distribution point specificied, but the extension value was not found"
            .to_string(),
        ));
    };
    let dp: (_, Any) =
        FromDer::from_der(distribution_points.data).map_err(|e| Error::MdocAuth(e.to_string()))?;
    if dp.1.tag().0 != 0 {
        errors.push(Error::MdocAuth(
            "reason and crlIssuer fields shall not be used in the crl distribution point"
                .to_string(),
        ));
    }

    // Issuer Alternative Name  2.5.29.18
    let Some(issuer_alternative_name) = root_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_ISSUER_ALTERNATIVE_NAME)
    else {
        return Err(Error::MdocAuth(
            "The root certificate is expected to have issuer alternative name specificied, but the extensions was not found".to_string()
        ));
    };

    let ian: (_, SequenceOf<Any>) =
        FromDer::from_der(issuer_alternative_name.extn_value.as_bytes())
            .map_err(|e| Error::MdocAuth(e.to_string()))?;
    for item in ian.1.iter() {
        if item.tag().0 != 1 && item.tag().0 != 6 {
            errors.push(Error::MdocAuth(format!(
                "issuer alternative name is expected to be an rfc822name or a URI, but found: {:?}",
                item
            )));
        }
    }

    Ok(errors)
}

pub fn validate_iaca_signer_extensions(
    leaf_extensions: Vec<Extension>,
) -> Result<Vec<Error>, Error> {
    let disallowed = iaca_disallowed_x509_extensions();
    let mut errors: Vec<Error> = vec![];
    for extension in leaf_extensions.clone() {
        if let Some(disallowed_extension) = disallowed
            .iter()
            .find(|oid| extension.extn_id.to_string() == **oid)
        {
            errors.push(Error::MdocAuth(format!(
                "The extension with oid: {:?} is not allowed in the IACA certificate profile",
                disallowed_extension
            )));
        }
    }

    let leaf_crit_extensions: Vec<&Extension> =
        leaf_extensions.iter().filter(|ext| ext.critical).collect();
    // Key Usage 2.5.29.15
    let Some(key_usage) = leaf_crit_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_KEY_USAGE)
    else {
        return Err(Error::MdocAuth(
            "Missing critical KeyUsage extension in the signer certificate".to_string(),
        ));
    };

    let decoded_key_usage_value: (_, BitString) =
        FromDer::from_der(key_usage.extn_value.as_bytes())
            .map_err(|e| Error::MdocAuth(e.to_string()))?;
    let Some(bitslice) = decoded_key_usage_value.1.as_bitslice() else {
        return Err(Error::MdocAuth(
            "Error decoding extension value as a bitslice".to_string(),
        ));
    };

    let leaf_key_usage_bit: Vec<usize> = bitslice.iter_ones().collect();
    if leaf_key_usage_bit.as_slice() != LEAF_KEY_USAGE {
        errors.push(Error::MdocAuth(
            "the signer certificate key usage extension is invalid".to_string(),
        ));
    }

    // Extended Key Usage     2.5.29.37
    let Some(extended_key_usage) = leaf_crit_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_EXTENDED_KEY_USAGE)
    else {
        return Err(Error::MdocAuth(
            "Missing critical ExtendedKeyUsage extension in the signer certificate".to_string(),
        ));
    };

    let ext_ku: (_, SequenceOf<Oid>) = FromDer::from_der(extended_key_usage.extn_value.as_bytes())
        .map_err(|e| Error::MdocAuth(e.to_string()))?;
    let Some(eku) = ext_ku.1.iter().next() else {
        return Err(Error::MdocAuth(
            "missing critical ExtendedKeyUsage value".to_string(),
        ));
    };

    if eku.to_id_string() != *EXTENDED_KEY_USAGE {
        errors.push(Error::MdocAuth(
            "Invalid value for Extended Key Usage in signer certificate to sign mDLs".to_string(),
        ));
    }

    //CRL Distribution Points  2.5.29.31
    let Some(crl_distribution_point) = leaf_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_CRL_DISTRIBUTION_POINTS)
    else {
        return Err(Error::MdocAuth(
            "The leaf certificate is expected to have a crl distribution point specificied, but the extensions was not found".to_string(),
        ));
    };

    let crl_dp: (_, SequenceOf<Any>) =
        FromDer::from_der(crl_distribution_point.extn_value.as_bytes())
            .map_err(|e| Error::MdocAuth(e.to_string()))?;
    let Some(distribution_points) = crl_dp.1.iter().next() else {
        return Err(Error::MdocAuth(
            "The leaf certificate is expected to have a crl distribution point specificied, but the extensions was not found".to_string(),
        ));
    };

    let dp: (_, Any) =
        FromDer::from_der(distribution_points.data).map_err(|e| Error::MdocAuth(e.to_string()))?;
    if !CRL_DISTRIBUTION_POINT.contains(&dp.1.tag().0) {
        errors.push(Error::MdocAuth(
            "reason and crlIssuer fields shall not be used in the crl distribution point"
                .to_string(),
        ));
    }

    // Issuer Alternative Name  2.5.29.18
    let Some(issuer_alternative_name) = leaf_extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == *OID_ISSUER_ALTERNATIVE_NAME)
    else {
        return Err(Error::MdocAuth("The leaf certificate is expected to have issuer alternative name specificied, but the extensions was not found".to_string()));
    };

    let ian: (_, SequenceOf<Any>) =
        FromDer::from_der(issuer_alternative_name.extn_value.as_bytes())
            .map_err(|e| Error::MdocAuth(e.to_string()))?;
    for item in ian.1.iter() {
        if !ISSUER_ALTERNATIVE_NAME.contains(&item.tag().0) {
            errors.push(Error::MdocAuth(format!(
                "issuer alternative name is expected to be an rfc822name or a URI, but found: {:?}",
                item
            )));
        }
    }

    Ok(errors)
}
