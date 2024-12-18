use const_oid::{AssociatedOid, ObjectIdentifier};
use der::Decode;
use sha1::{Digest, Sha1};
use x509_cert::{
    ext::{pkix::SubjectKeyIdentifier, Extension},
    Certificate,
};

use super::Error;
use super::ExtensionValidator;

pub struct SubjectKeyIdentifierValidator {
    subject_public_key_bitstring_raw_bytes: Vec<u8>,
}

impl SubjectKeyIdentifierValidator {
    pub fn from_certificate(certificate: &Certificate) -> Self {
        Self {
            subject_public_key_bitstring_raw_bytes: certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes()
                .to_owned(),
        }
    }

    fn check(&self, ski: SubjectKeyIdentifier) -> Option<Error> {
        let expected_digest = ski.0.as_bytes();
        let digest = Sha1::digest(&self.subject_public_key_bitstring_raw_bytes);

        if digest.as_slice() != expected_digest {
            Some("public key digest did not match the expected value".into())
        } else {
            None
        }
    }
}

impl ExtensionValidator for SubjectKeyIdentifierValidator {
    fn oid(&self) -> ObjectIdentifier {
        SubjectKeyIdentifier::OID
    }

    fn ext_name(&self) -> &'static str {
        "SubjectKeyIdentifier"
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let ski = SubjectKeyIdentifier::from_der(bytes);
        match ski {
            Ok(ski) => {
                if let Some(e) = self.check(ski) {
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
#[case::ok(
    include_str!("../../../../../test/issuance/256-cert.pem"),
    include_str!("../../../../../test/issuance/256-cert.pem"),
    true
)]
#[case::different_cert_ski_ext(
    include_str!("../../../../../test/issuance/256-cert.pem"),
    include_str!("../../../../../test/issuance/384-cert.pem"),
    false
)]
fn test(
    #[case] public_key_from_certificate_pem: &'static str,
    #[case] ski_ext_from_certificate_pem: &'static str,
    #[case] valid: bool,
) {
    use der::DecodePem;

    let certificate = Certificate::from_pem(public_key_from_certificate_pem).unwrap();
    let skiv = SubjectKeyIdentifierValidator::from_certificate(&certificate);

    let certificate = Certificate::from_pem(ski_ext_from_certificate_pem).unwrap();
    let outcome = skiv.validate(
        certificate
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .filter(|ext| ext.extn_id == skiv.oid())
            .next()
            .unwrap(),
    );
    assert_eq!(outcome.is_empty(), valid)
}
