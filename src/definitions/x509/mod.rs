pub mod crl;
pub mod trust_anchor;
mod util;
pub mod validation;
pub mod x5chain;

pub use util::SupportedCurve;
pub use x5chain::{Builder, X5Chain};

#[cfg(test)]
pub(crate) mod test {
    use std::time::Duration;

    use const_oid::ObjectIdentifier;
    use der::asn1::OctetString;
    use p256::NistP256;
    use rand::random;
    use sec1::pkcs8::EncodePublicKey;
    use sha1::{Digest, Sha1};
    use signature::{Keypair, KeypairRef, Signer};
    use x509_cert::{
        builder::{Builder, CertificateBuilder},
        ext::pkix::{
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName},
            AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage,
            IssuerAltName, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
        name::Name,
        spki::{
            DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
        },
        time::Validity,
        Certificate,
    };

    use super::validation;

    pub(crate) fn prepare_root_certificate<S>(
        root_key: &S,
        issuer: Name,
        crl_url: String,
    ) -> CertificateBuilder<'_, S>
    where
        S: KeypairRef + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let spki = SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key()).unwrap();
        let ski_digest = Sha1::digest(spki.subject_public_key.raw_bytes());
        let ski_digest_octet = OctetString::new(ski_digest.to_vec()).unwrap();

        let mut builder = CertificateBuilder::new(
            x509_cert::builder::Profile::Manual { issuer: None },
            random::<u64>().into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            issuer,
            spki,
            root_key,
        )
        .unwrap();

        builder
            .add_extension(&SubjectKeyIdentifier(ski_digest_octet))
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
                    GeneralName::UniformResourceIdentifier(crl_url.try_into().unwrap()),
                ])),
                reasons: None,
                crl_issuer: None,
            }]))
            .unwrap();

        builder
    }

    pub(crate) fn prepare_signer_certificate<'s, S>(
        signer_key: &'s S,
        root_key: &'s S,
        issuer: Name,
        crl_url: String,
    ) -> CertificateBuilder<'s, S>
    where
        S: KeypairRef + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let spki = SubjectPublicKeyInfoOwned::from_key(signer_key.verifying_key()).unwrap();
        let ski_digest = Sha1::digest(spki.subject_public_key.raw_bytes());
        let ski_digest_octet = OctetString::new(ski_digest.to_vec()).unwrap();

        let apki = SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key()).unwrap();
        let aki_digest = Sha1::digest(apki.subject_public_key.raw_bytes());
        let aki_digest_octet = OctetString::new(aki_digest.to_vec()).unwrap();

        let mut builder = CertificateBuilder::new(
            x509_cert::builder::Profile::Manual {
                issuer: Some(issuer),
            },
            random::<u64>().into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            "CN=subject,C=US".parse().unwrap(),
            spki,
            root_key,
        )
        .unwrap();

        builder
            .add_extension(&SubjectKeyIdentifier(ski_digest_octet))
            .unwrap();

        builder
            .add_extension(&AuthorityKeyIdentifier {
                key_identifier: Some(aki_digest_octet),
                ..Default::default()
            })
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
                    GeneralName::UniformResourceIdentifier(crl_url.try_into().unwrap()),
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
        let (root, signer, _, _) = setup_with_crl_url("http://example.com/crl".to_string());
        (root, signer)
    }

    /// Setup test certificates with a custom CRL URL.
    /// Returns (root_cert, signer_cert, root_key, issuer_name).
    pub(crate) fn setup_with_crl_url(
        crl_url: String,
    ) -> (Certificate, Certificate, p256::ecdsa::SigningKey, Name) {
        let root_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let signer_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());

        let issuer: Name = "CN=issuer,C=US".parse().unwrap();

        let mut prepared_root_certificate =
            prepare_root_certificate(&root_key, issuer.clone(), crl_url.clone());
        let signature: ecdsa::Signature<NistP256> =
            root_key.sign(&prepared_root_certificate.finalize().unwrap());
        let root_certificate: Certificate = prepared_root_certificate
            .assemble(signature.to_der().to_bitstring().unwrap())
            .unwrap();

        let mut prepared_signer_certificate =
            prepare_signer_certificate(&signer_key, &root_key, issuer.clone(), crl_url);
        let signature: ecdsa::Signature<NistP256> =
            root_key.sign(&prepared_signer_certificate.finalize().unwrap());
        let signer_certificate: Certificate = prepared_signer_certificate
            .assemble(signature.to_der().to_bitstring().unwrap())
            .unwrap();

        assert!(validation::signature::issuer_signed_subject(
            &signer_certificate,
            &root_certificate
        ));

        (root_certificate, signer_certificate, root_key, issuer)
    }

    mod iaca {
        use der::EncodePem;

        use crate::definitions::x509::{
            trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose},
            validation::ValidationRuleset,
            X5Chain,
        };

        #[test_log::test(tokio::test)]
        async fn valid_mdoc_issuer_certificate_chain_is_validated() {
            let (root, signer) = super::setup();

            tracing::debug!(
                "issuer certificate:\n{}",
                root.to_pem(Default::default()).unwrap()
            );
            tracing::debug!(
                "signer certificate:\n{}",
                signer.to_pem(Default::default()).unwrap()
            );

            let trust_anchor_registry = TrustAnchorRegistry {
                anchors: vec![TrustAnchor {
                    certificate: root,
                    purpose: TrustPurpose::Iaca,
                }],
            };
            let x5chain = X5Chain::builder()
                .with_certificate(signer)
                .unwrap()
                .build()
                .unwrap();
            // Use () to skip CRL checking in tests
            let outcome = ValidationRuleset::Mdl
                .validate(&x5chain, &trust_anchor_registry, &())
                .await;
            assert!(outcome.success(), "{outcome:?}");
        }
    }
}
