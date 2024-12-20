use const_oid::AssociatedOid;
use const_oid::ObjectIdentifier;
use der::Decode;
use x509_cert::ext::{pkix::ExtendedKeyUsage, Extension};

use super::Error;
use super::ExtensionValidator;

/// ExtendedKeyUsage validation for document signer and mdoc reader certificates.
pub struct ExtendedKeyUsageValidator {
    pub expected_oid: ObjectIdentifier,
}

impl ExtendedKeyUsageValidator {
    fn check(&self, eku: ExtendedKeyUsage) -> Option<Error> {
        if !eku.0.iter().all(|oid| *oid == self.expected_oid) {
            Some(format!(
                "expected '{}', found '{:?}'",
                self.expected_oid, eku.0
            ))
        } else if eku.0.is_empty() {
            Some(format!("expected '{}', found '[]'", self.expected_oid))
        } else {
            None
        }
    }
}

impl ExtensionValidator for ExtendedKeyUsageValidator {
    fn oid(&self) -> const_oid::ObjectIdentifier {
        ExtendedKeyUsage::OID
    }

    fn ext_name(&self) -> &'static str {
        "ExtendedKeyUsage"
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let extended_key_usage = ExtendedKeyUsage::from_der(bytes);

        if !extension.critical {
            tracing::warn!("expected ExtendedKeyUsage extension to be critical",)
        }

        match extended_key_usage {
            Ok(eku) => {
                if let Some(e) = self.check(eku) {
                    vec![e]
                } else {
                    vec![]
                }
            }
            Err(e) => {
                vec![format!("failed to decode: {e}")]
            }
        }
    }
}

pub const fn document_signer_extended_key_usage_oid() -> ObjectIdentifier {
    // Unwrap safety: unit tested.
    ObjectIdentifier::new_unwrap("1.0.18013.5.1.2")
}

pub const fn mdoc_reader_extended_key_usage_oid() -> ObjectIdentifier {
    // Unwrap safety: unit tested.
    ObjectIdentifier::new_unwrap("1.0.18013.5.1.6")
}

#[cfg(test)]
#[rstest::rstest]
#[case::ok(ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.1.1")]), true)]
#[case::wrong(ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.1.0")]), false)]
#[case::missing(ExtendedKeyUsage(vec![]), false)]
#[case::good_and_bad(ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.1.1"), ObjectIdentifier::new_unwrap("1.1.0")]), false)]
fn test(#[case] eku: ExtendedKeyUsage, #[case] valid: bool) {
    let outcome = ExtendedKeyUsageValidator {
        expected_oid: ObjectIdentifier::new_unwrap("1.1.1"),
    }
    .check(eku);
    assert_eq!(outcome.is_none(), valid)
}

#[cfg(test)]
#[test]
fn test_document_signer_extended_key_usage_oid() {
    document_signer_extended_key_usage_oid();
}

#[cfg(test)]
#[test]
fn test_mdoc_reader_extended_key_usage_oid() {
    mdoc_reader_extended_key_usage_oid();
}
