pub mod error;
pub mod extensions;
pub mod trust_anchor;
pub mod x5chain;

pub use x5chain::{Builder, X5Chain};

#[cfg(test)]
mod test {
    use std::time::Duration;

    use const_oid::ObjectIdentifier;
    use p256::NistP256;
    use rand::random;
    use sec1::pkcs8::EncodePublicKey;
    use signature::{Keypair, KeypairRef, Signer};
    use x509_cert::{
        builder::{Builder, CertificateBuilder},
        ext::pkix::{
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName},
            BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage, IssuerAltName, KeyUsage,
            KeyUsages,
        },
        name::Name,
        spki::{
            DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
        },
        time::Validity,
        Certificate,
    };

    fn prepare_root_certificate<S>(root_key: &S, issuer: Name) -> CertificateBuilder<'_, S>
    where
        S: KeypairRef + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let mut builder = CertificateBuilder::new(
            x509_cert::builder::Profile::Manual { issuer: None },
            random::<u64>().into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            issuer,
            SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key()).unwrap(),
            root_key,
        )
        .unwrap();

        builder
            .add_extension(&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign))
            .unwrap();

        builder
            .add_extension(&BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            })
            .unwrap();

        builder
            .add_extension(&IssuerAltName(vec![GeneralName::Rfc822Name(
                "test@example.com".to_string().try_into().unwrap(),
            )]))
            .unwrap();

        builder
            .add_extension(&CrlDistributionPoints(vec![DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::UniformResourceIdentifier(
                        "http://example.com".to_string().try_into().unwrap(),
                    ),
                ])),
                reasons: None,
                crl_issuer: None,
            }]))
            .unwrap();

        builder
    }

    fn prepare_signer_certificate<'s, S>(
        signer_key: &'s S,
        root_key: &'s S,
        issuer: Name,
    ) -> CertificateBuilder<'s, S>
    where
        S: KeypairRef + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let mut builder = CertificateBuilder::new(
            x509_cert::builder::Profile::Manual {
                issuer: Some(issuer),
            },
            random::<u64>().into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            Name::default(),
            SubjectPublicKeyInfoOwned::from_key(signer_key.verifying_key()).unwrap(),
            root_key,
        )
        .unwrap();

        builder
            .add_extension(&KeyUsage(KeyUsages::DigitalSignature.into()))
            .unwrap();

        builder
            .add_extension(&IssuerAltName(vec![GeneralName::Rfc822Name(
                "test@example.com".to_string().try_into().unwrap(),
            )]))
            .unwrap();

        builder
            .add_extension(&CrlDistributionPoints(vec![DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::UniformResourceIdentifier(
                        "http://example.com".to_string().try_into().unwrap(),
                    ),
                ])),
                reasons: None,
                crl_issuer: None,
            }]))
            .unwrap();

        builder
            .add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
                "1.0.18013.5.1.2",
            )]))
            .unwrap();

        builder
    }

    fn setup() -> (Certificate, Certificate) {
        let root_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let signer_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());

        let issuer = Name::default();

        let mut prepared_root_certificate = prepare_root_certificate(&root_key, issuer.clone());
        let signature: ecdsa::der::Signature<NistP256> =
            root_key.sign(&prepared_root_certificate.finalize().unwrap());
        let root_certificate: Certificate = prepared_root_certificate
            .assemble(signature.to_bitstring().unwrap())
            .unwrap();

        let mut prepared_signer_certificate =
            prepare_signer_certificate(&signer_key, &root_key, issuer.clone());
        let signature: ecdsa::der::Signature<NistP256> =
            root_key.sign(&prepared_signer_certificate.finalize().unwrap());
        let signer_certificate: Certificate = prepared_signer_certificate
            .assemble(signature.to_bitstring().unwrap())
            .unwrap();

        (root_certificate, signer_certificate)
    }

    mod iaca {
        use crate::definitions::x509::{
            trust_anchor::{TrustAnchor, TrustAnchorRegistry},
            X5Chain,
        };

        #[test_log::test]
        fn valid_certificate_chain_is_validated() {
            let (root, signer) = super::setup();
            let trust_anchor_registry = TrustAnchorRegistry {
                certificates: vec![TrustAnchor::Iaca(root)],
            };
            let x5chain = X5Chain::builder()
                .with_certificate(signer)
                .unwrap()
                .build()
                .unwrap();
            let errors = x5chain.validate(Some(&trust_anchor_registry));
            assert!(errors.is_empty(), "{errors:?}");
        }
    }
}
