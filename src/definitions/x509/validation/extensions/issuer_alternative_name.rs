use const_oid::AssociatedOid;
use const_oid::ObjectIdentifier;
use der::Decode;
use x509_cert::ext::{
    pkix::{name::GeneralName, IssuerAltName},
    Extension,
};

use super::Error;
use super::ExtensionValidator;

pub struct IssuerAlternativeNameValidator;

impl IssuerAlternativeNameValidator {
    fn check(ian: IssuerAltName) -> Option<Error> {
        if !ian.0.iter().all(|gn| {
            matches!(
                gn,
                GeneralName::Rfc822Name(_) | GeneralName::UniformResourceIdentifier(_)
            )
        }) {
            Some(format!(
                "invalid type in found in general names: {:?}",
                ian.0
            ))
        } else {
            None
        }
    }
}

impl ExtensionValidator for IssuerAlternativeNameValidator {
    fn oid(&self) -> ObjectIdentifier {
        IssuerAltName::OID
    }

    fn ext_name(&self) -> &'static str {
        "IssuerAlternativeName"
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let iss_altname = IssuerAltName::from_der(bytes);
        match iss_altname {
            Ok(ian) => {
                if let Some(e) = Self::check(ian) {
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
