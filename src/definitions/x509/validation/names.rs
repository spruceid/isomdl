use const_oid::{
    db::{self, rfc2256::STATE_OR_PROVINCE_NAME, rfc4519::COUNTRY_NAME},
    ObjectIdentifier,
};
use x509_cert::{attr::AttributeValue, Certificate};

use crate::definitions::x509::util::{attribute_value_to_str, common_name_or_unknown};

#[derive(Debug, Copy, Clone, thiserror::Error)]
pub enum Error<'l> {
    #[error("'{certificate_common_name}' has no subject '{name}'")]
    Missing {
        certificate_common_name: &'l str,
        name: &'static str,
    },
    #[error("'{certificate_common_name}' has multiple subject '{name}'s")]
    Multiple {
        certificate_common_name: &'l str,
        name: &'static str,
    },
    #[error("subject '{name}' does not match: {this} != {that}")]
    Mismatch {
        name: &'static str,
        this: &'l str,
        that: &'l str,
    },
}

#[allow(dead_code)]
/// Checks that countryName in the certificate has only one countryName in the subject and that it
/// matches the expected value.
pub fn country_name_is<'a: 'c, 'b: 'c, 'c>(
    certificate: &'a Certificate,
    expected_country_name: &'b str,
) -> Option<Error<'c>> {
    let name = "countryName";

    let mut cs = get_rdns(certificate, COUNTRY_NAME);

    let Some(c) = cs.next() else {
        return Some(Error::Missing {
            certificate_common_name: common_name_or_unknown(certificate),
            name,
        });
    };

    if cs.next().is_some() {
        return Some(Error::Multiple {
            certificate_common_name: common_name_or_unknown(certificate),
            name,
        });
    }

    let c = attribute_value_to_str(c).unwrap_or("unknown");

    if c != expected_country_name {
        return Some(Error::Mismatch {
            name,
            this: c,
            that: expected_country_name,
        });
    }

    None
}

/// Checks that each certificate has only one countryName in the subject, and that they match.
pub fn country_name_matches<'a: 'c, 'b: 'c, 'c>(
    this: &'a Certificate,
    that: &'b Certificate,
) -> Option<Error<'c>> {
    name_matches(COUNTRY_NAME, this, that)
}

/// Checks that each certificate has only one stateOrProvinceName in the subject, and that they match.
pub fn state_or_province_name_matches<'a: 'c, 'b: 'c, 'c>(
    this: &'a Certificate,
    that: &'b Certificate,
) -> Option<Error<'c>> {
    name_matches(STATE_OR_PROVINCE_NAME, this, that)
}

fn name_matches<'a: 'c, 'b: 'c, 'c>(
    name_oid: ObjectIdentifier,
    this: &'a Certificate,
    that: &'b Certificate,
) -> Option<Error<'c>> {
    let name = db::DB.by_oid(&name_oid).unwrap_or("unknown");

    let mut this_cs = get_rdns(this, name_oid);
    let mut that_cs = get_rdns(that, name_oid);

    let Some(this_c) = this_cs.next() else {
        return Some(Error::Missing {
            certificate_common_name: common_name_or_unknown(this),
            name,
        });
    };

    let Some(that_c) = that_cs.next() else {
        return Some(Error::Missing {
            certificate_common_name: common_name_or_unknown(that),
            name,
        });
    };

    if this_cs.next().is_some() {
        return Some(Error::Multiple {
            certificate_common_name: common_name_or_unknown(that),
            name,
        });
    }

    if that_cs.next().is_some() {
        return Some(Error::Multiple {
            certificate_common_name: common_name_or_unknown(this),
            name,
        });
    }

    if this_c != that_c {
        return Some(Error::Mismatch {
            name,
            this: attribute_value_to_str(this_c).unwrap_or("Unknown"),
            that: attribute_value_to_str(that_c).unwrap_or("Unknown"),
        });
    }

    None
}

/// Check whether the certificate has a particular RelativeDistinguished name in the subject.
pub fn has_rdn(certificate: &Certificate, oid: ObjectIdentifier) -> bool {
    get_rdns(certificate, oid).next().is_some()
}

fn get_rdns(
    certificate: &Certificate,
    oid: ObjectIdentifier,
) -> impl Iterator<Item = &AttributeValue> {
    certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter_map(move |attribute| {
            if attribute.oid == oid {
                Some(&attribute.value)
            } else {
                None
            }
        })
}
