use const_oid::AssociatedOid;
use der::Decode;
use x509_cert::ext::{pkix::BasicConstraints, Extension};

use super::{Error, ExtensionValidator};

/// BasicConstraints validation for IACA certificate.
pub struct BasicConstraintsValidator;

impl BasicConstraintsValidator {
    fn check(constraints: BasicConstraints) -> Option<Error> {
        if constraints
            .path_len_constraint
            .is_none_or(|path_len| path_len != 0)
            || !constraints.ca
        {
            Some(format!(
                "expected to be CA:true, path_len:0, but found: {constraints:?}"
            ))
        } else {
            None
        }
    }
}

impl ExtensionValidator for BasicConstraintsValidator {
    fn oid(&self) -> const_oid::ObjectIdentifier {
        BasicConstraints::OID
    }

    fn ext_name(&self) -> &'static str {
        "BasicConstraints"
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let mut errors = vec![];

        if !extension.critical {
            tracing::warn!("expected BasicConstraints extension to be critical",)
        }

        let bytes = extension.extn_value.as_bytes();
        let basic_constraints = BasicConstraints::from_der(bytes);
        match basic_constraints {
            Ok(bc) => {
                if let Some(e) = Self::check(bc) {
                    errors.push(e);
                }
            }
            Err(e) => errors.push(format!("failed to decode: {e}")),
        }

        errors
    }
}

#[cfg(test)]
#[rstest::rstest]
#[case::ok(BasicConstraints { ca: true, path_len_constraint: Some(0) }, true)]
#[case::ca_false(BasicConstraints { ca: false, path_len_constraint: Some(0) }, false)]
#[case::path_none(BasicConstraints { ca: true, path_len_constraint: None }, false)]
#[case::path_too_long(BasicConstraints { ca: true, path_len_constraint: Some(1) }, false)]
#[case::both_wrong(BasicConstraints { ca: false, path_len_constraint: None }, false)]
fn test(#[case] bc: BasicConstraints, #[case] valid: bool) {
    let outcome = BasicConstraintsValidator::check(bc);
    assert_eq!(outcome.is_none(), valid)
}
