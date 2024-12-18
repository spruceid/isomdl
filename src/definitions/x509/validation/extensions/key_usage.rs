use const_oid::AssociatedOid;
use der::{flagset::FlagSet, Decode};
use x509_cert::ext::{
    pkix::{KeyUsage, KeyUsages},
    Extension,
};

use super::{Error, ExtensionValidator};

/// KeyUsage validation for all certificate profiles.
pub struct KeyUsageValidator {
    expected_flagset: FlagSet<KeyUsages>,
}

impl KeyUsageValidator {
    pub fn document_signer() -> Self {
        Self {
            expected_flagset: KeyUsages::DigitalSignature.into(),
        }
    }

    pub fn mdoc_reader() -> Self {
        Self {
            expected_flagset: KeyUsages::DigitalSignature.into(),
        }
    }

    pub fn iaca() -> Self {
        Self {
            expected_flagset: KeyUsages::CRLSign | KeyUsages::KeyCertSign,
        }
    }

    fn check(&self, ku: KeyUsage) -> Option<Error> {
        if ku.0 != self.expected_flagset {
            Some(format!(
                "unexpected usage: {:?}",
                ku.0.into_iter().collect::<Vec<KeyUsages>>()
            ))
        } else {
            None
        }
    }
}

impl ExtensionValidator for KeyUsageValidator {
    fn oid(&self) -> const_oid::ObjectIdentifier {
        KeyUsage::OID
    }

    fn ext_name(&self) -> &'static str {
        "KeyUsage"
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let key_usage = KeyUsage::from_der(bytes);

        if !extension.critical {
            tracing::warn!("expected KeyUsage extension to be critical",)
        }

        match key_usage {
            Ok(ku) => {
                if let Some(e) = self.check(ku) {
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

#[cfg(test)]
#[rstest::rstest]
#[case::ds_ok(KeyUsageValidator::document_signer(), KeyUsage(KeyUsages::DigitalSignature.into()), true)]
#[case::iaca_ok(KeyUsageValidator::iaca(), KeyUsage(KeyUsages::CRLSign | KeyUsages::KeyCertSign), true)]
#[case::ds_extra(KeyUsageValidator::iaca(), KeyUsage( KeyUsages::KeyCertSign | KeyUsages::DigitalSignature), false)]
#[case::iaca_extra(KeyUsageValidator::iaca(), KeyUsage(KeyUsages::CRLSign | KeyUsages::KeyCertSign | KeyUsages::DigitalSignature), false)]
#[case::ds_missing(KeyUsageValidator::iaca(), KeyUsage(FlagSet::default()), false)]
#[case::iaca_missing(KeyUsageValidator::iaca(), KeyUsage(KeyUsages::KeyCertSign.into()), false)]
fn test(#[case] kuv: KeyUsageValidator, #[case] ku: KeyUsage, #[case] valid: bool) {
    let outcome = kuv.check(ku);
    assert_eq!(outcome.is_none(), valid)
}

#[cfg(test)]
#[test]
fn test_flagsets() {
    assert!(KeyUsageValidator::document_signer()
        .expected_flagset
        .contains(KeyUsages::DigitalSignature));
    assert!(KeyUsageValidator::mdoc_reader()
        .expected_flagset
        .contains(KeyUsages::DigitalSignature));
    assert!(KeyUsageValidator::iaca()
        .expected_flagset
        .contains(KeyUsages::CRLSign));
    assert!(KeyUsageValidator::iaca()
        .expected_flagset
        .contains(KeyUsages::KeyCertSign));
}
