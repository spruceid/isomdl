use std::time::Duration;

use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::Decode;
use p256::NistP256;
use rand::random;
use sec1::pkcs8::EncodePublicKey;
use sha1::{Digest, Sha1};
use signature::{Keypair, KeypairRef, Signer};
use x509_cert::{
    builder::{Builder, CertificateBuilder},
    crl::{CertificateList, RevokedCert, TbsCertList},
    ext::{
        pkix::{
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName},
            AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage,
            IssuerAltName, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{
        DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
    },
    time::{Time, Validity},
    Certificate, Version,
};

use super::{revocation, trust_anchor, validation, X5Chain};

/// The EKU that ISO/IEC 18013-5 requires on a document signer certificate.
pub(crate) const EKU_MDOC_DS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.0.18013.5.1.2");
/// The EKU that ISO/IEC 18013-5 requires on an mdoc reader certificate.
pub(crate) const EKU_MDOC_READER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.0.18013.5.1.6");

/// The default certificate lifetime used by the pre-existing helpers.
///
/// Ten minutes is short enough that any test pinning a validation time outside the
/// window fails on *certificate* validity rather than on the thing under test. Tests
/// that pin time should pass their own [`Validity`].
pub(crate) fn default_validity() -> Validity {
    Validity::from_now(Duration::from_secs(600)).unwrap()
}

pub(crate) fn prepare_root_certificate<S>(
    root_key: &S,
    issuer: Name,
    crl_url: String,
    validity: Validity,
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
        validity,
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
    subject: Name,
    crl_url: String,
    validity: Validity,
    eku: ObjectIdentifier,
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
        validity,
        subject,
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

    builder.add_extension(&ExtendedKeyUsage(vec![eku])).unwrap();

    builder
}

/// A document signer certificate shaped like an ETSI EN 319 411-1 NCP one, as the EU age
/// verification profile requires, rather than like an ISO/IEC 18013-5 Annex B one.
///
/// The differences are the point: no `IssuerAlternativeName`, no CRL distribution point,
/// and a certificate policy OID instead of an mdoc `extendedKeyUsage`. None of those is an
/// OID *value* an [`MdocProfile`](crate::definitions::x509::validation::MdocProfile) could
/// be pointed at — they are checks that do or do not apply.
///
/// `0.4.0.2042.1.1` is ETSI's NCP policy identifier.
pub(crate) fn prepare_etsi_style_signer_certificate<'s, S>(
    signer_key: &'s S,
    root_key: &'s S,
    issuer: Name,
    validity: Validity,
    policy: ObjectIdentifier,
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
        validity,
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
        .add_extension(&x509_cert::ext::pkix::CertificatePolicies(vec![
            x509_cert::ext::pkix::certpolicy::PolicyInformation {
                policy_qualifiers: None,
                policy_identifier: policy,
            },
        ]))
        .unwrap();

    builder
}

fn setup() -> (Certificate, Certificate) {
    let (root, signer, _, _) = setup_with_crl_url("http://example.com/crl".to_string());
    (root, signer)
}

/// A freshly minted two-level PKI: a self-signed root and a leaf it signed.
///
/// Unlike [`setup_with_crl_url`] this keeps `leaf_key`, which is what lets a test both
/// *issue* an mdoc and *validate* the chain it was issued under.
pub(crate) struct TestPki {
    pub root: Certificate,
    pub leaf: Certificate,
    pub root_key: p256::ecdsa::SigningKey,
    pub leaf_key: p256::ecdsa::SigningKey,
    pub issuer: Name,
}

impl TestPki {
    /// A PKI whose leaf is a document signer — the common case.
    pub fn issuer() -> Self {
        Self::generate(Self::CRL_URL.to_string(), default_validity(), EKU_MDOC_DS)
    }

    /// A PKI whose leaf is an mdoc reader.
    pub fn reader() -> Self {
        Self::generate(
            Self::CRL_URL.to_string(),
            default_validity(),
            EKU_MDOC_READER,
        )
    }

    /// `validity` is a parameter because [`default_validity`] is only ten minutes
    /// wide: a test that pins its validation time outside that window fails on
    /// *certificate* validity rather than on whatever it meant to check. Prefer
    /// moving the MSO's [`ValidityInfo`](crate::definitions::ValidityInfo) over
    /// pinning validation time — pinning moves the certificate window too.
    ///
    /// `crl_url` goes into the root's CRL distribution point extension; see
    /// [`prepare_root_certificate`]. Use [`Self::CRL_URL`] unless the test
    /// exercises CRL fetching from a specific URL.
    pub fn generate(crl_url: String, validity: Validity, eku: ObjectIdentifier) -> Self {
        Self::generate_with_signer_subject(crl_url, validity, eku, Self::DEFAULT_SUBJECT)
    }

    /// [`generate`](Self::generate) with a document signer subject of your choosing, for
    /// tests about how the signer's and root's names are compared.
    pub fn generate_with_signer_subject(
        crl_url: String,
        validity: Validity,
        eku: ObjectIdentifier,
        subject: &str,
    ) -> Self {
        let root_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let leaf_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());

        let issuer: Name = "CN=issuer,C=US".parse().unwrap();

        let mut prepared_root =
            prepare_root_certificate(&root_key, issuer.clone(), crl_url.clone(), validity);
        let signature: ecdsa::Signature<NistP256> =
            root_key.sign(&prepared_root.finalize().unwrap());
        let root: Certificate = prepared_root
            .assemble(signature.to_der().to_bitstring().unwrap())
            .unwrap();

        let mut prepared_leaf = prepare_signer_certificate(
            &leaf_key,
            &root_key,
            issuer.clone(),
            subject.parse().unwrap(),
            crl_url,
            validity,
            eku,
        );
        let signature: ecdsa::Signature<NistP256> =
            root_key.sign(&prepared_leaf.finalize().unwrap());
        let leaf: Certificate = prepared_leaf
            .assemble(signature.to_der().to_bitstring().unwrap())
            .unwrap();

        assert!(validation::signature::issuer_signed_subject(&leaf, &root));

        Self {
            root,
            leaf,
            root_key,
            leaf_key,
            issuer,
        }
    }

    /// A PKI whose document signer follows ETSI EN 319 411-1 NCP rather than
    /// ISO/IEC 18013-5 Annex B — the shape the EU age verification profile requires.
    ///
    /// See [`prepare_etsi_style_signer_certificate`]. The root is still an Annex B IACA,
    /// which isolates the leaf's profile as the only thing under test.
    pub fn etsi_av() -> Self {
        Self::etsi_av_with_policy(validation::NCP_POLICY_OID)
    }

    /// [`etsi_av`](Self::etsi_av) asserting a certificate policy of your choosing, for
    /// tests that need a signer whose policy is present but wrong.
    pub fn etsi_av_with_policy(policy: ObjectIdentifier) -> Self {
        let root_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let leaf_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let issuer: Name = "CN=issuer,C=US".parse().unwrap();
        let validity = default_validity();

        let mut prepared_root = prepare_root_certificate(
            &root_key,
            issuer.clone(),
            Self::CRL_URL.to_string(),
            validity,
        );
        let signature: ecdsa::Signature<NistP256> =
            root_key.sign(&prepared_root.finalize().unwrap());
        let root: Certificate = prepared_root
            .assemble(signature.to_der().to_bitstring().unwrap())
            .unwrap();

        let mut prepared_leaf = prepare_etsi_style_signer_certificate(
            &leaf_key,
            &root_key,
            issuer.clone(),
            validity,
            policy,
        );
        let signature: ecdsa::Signature<NistP256> =
            root_key.sign(&prepared_leaf.finalize().unwrap());
        let leaf: Certificate = prepared_leaf
            .assemble(signature.to_der().to_bitstring().unwrap())
            .unwrap();

        assert!(validation::signature::issuer_signed_subject(&leaf, &root));

        Self {
            root,
            leaf,
            root_key,
            leaf_key,
            issuer,
        }
    }

    /// The distribution point named by every certificate this PKI mints.
    ///
    /// The IACA profile makes a CRL distribution point mandatory, so there is no
    /// "no CRL" configuration to fall back on — [`TestPki::fetcher`] serves this URL.
    pub const CRL_URL: &'static str = "http://example.com/crl";
    /// The subject both [`prepare_root_certificate`] and [`prepare_signer_certificate`]
    /// use, so a chain matches on `countryName` unless a test asks for otherwise.
    pub const DEFAULT_SUBJECT: &'static str = "CN=subject,C=US";

    /// A revocation fetcher that serves this PKI's own, empty, correctly signed CRL.
    ///
    /// Prefer this over `&()` whenever a test asserts on warnings: `&()` reports
    /// "no CRL fetcher configured" as a revocation warning, which is an artifact of
    /// the test setup rather than anything about the credential.
    pub fn fetcher(&self) -> StaticCrlFetcher {
        self.fetcher_revoking(&[])
    }

    /// Like [`TestPki::fetcher`], but the CRL lists `revoked_serials` as revoked.
    pub fn fetcher_revoking(&self, revoked_serials: &[SerialNumber]) -> StaticCrlFetcher {
        let der = create_crl(
            self.issuer.clone(),
            &self.root,
            &self.root_key,
            revoked_serials,
        );
        StaticCrlFetcher {
            crl: CertificateList::from_der(&der).expect("built an undecodable CRL"),
        }
    }

    /// This PKI's leaf serial number, for [`TestPki::fetcher_revoking`].
    pub fn leaf_serial(&self) -> SerialNumber {
        self.leaf.tbs_certificate.serial_number.clone()
    }

    /// The chain to embed in an issuer-signed COSE header.
    pub fn x5chain(&self) -> X5Chain {
        X5Chain::builder()
            .with_certificate(self.leaf.clone())
            .unwrap()
            .build()
            .unwrap()
    }

    pub fn registry(
        &self,
        purpose: trust_anchor::TrustPurpose,
    ) -> trust_anchor::TrustAnchorRegistry {
        trust_anchor::TrustAnchorRegistry {
            anchors: vec![trust_anchor::TrustAnchor {
                certificate: self.root.clone(),
                purpose,
            }],
        }
    }

    pub fn iaca_registry(&self) -> trust_anchor::TrustAnchorRegistry {
        self.registry(trust_anchor::TrustPurpose::Iaca)
    }
}

/// Serves one fixed CRL for every URL asked of it.
///
/// No HTTP involved, so it works without the `reqwest` feature.
pub(crate) struct StaticCrlFetcher {
    crl: CertificateList,
}

#[async_trait::async_trait]
impl revocation::RevocationFetcher for StaticCrlFetcher {
    async fn fetch_crl(&self, _url: &str) -> Result<CertificateList, revocation::CrlError> {
        Ok(self.crl.clone())
    }
}

/// Build CRL extensions per ISO 18013-5 Table B.10:
/// - Authority Key Identifier (5.2.1, M) with keyIdentifier matching the IACA's SKI
/// - CRL Number (5.2.3, M)
pub(crate) fn build_crl_extensions(root_cert: &Certificate) -> Vec<Extension> {
    use const_oid::AssociatedOid;
    use der::Encode;

    let ski = root_cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|ext| ext.extn_id == SubjectKeyIdentifier::OID)
        .expect("root certificate must have SKI");
    let ski =
        SubjectKeyIdentifier::from_der(ski.extn_value.as_bytes()).expect("valid SKI extension");

    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new(ski.0.as_bytes().to_vec()).unwrap()),
        ..Default::default()
    };
    let aki_ext = Extension {
        extn_id: revocation::OID_AUTHORITY_KEY_IDENTIFIER,
        critical: false,
        extn_value: OctetString::new(aki.to_der().unwrap()).unwrap(),
    };

    let crl_number_ext = Extension {
        extn_id: revocation::OID_CRL_NUMBER,
        critical: false,
        extn_value: OctetString::new(1u64.to_der().unwrap()).unwrap(),
    };

    vec![aki_ext, crl_number_ext]
}

/// A CRL signed by `root_key`, listing `revoked_serials` as revoked.
pub(crate) fn create_crl(
    issuer: Name,
    root_cert: &Certificate,
    root_key: &p256::ecdsa::SigningKey,
    revoked_serials: &[SerialNumber],
) -> Vec<u8> {
    use der::Encode;

    let now = std::time::SystemTime::now();
    let this_update = Time::try_from(now).unwrap();
    let next_update = Time::try_from(now + Duration::from_secs(86400)).unwrap();

    let revoked_certificates = if revoked_serials.is_empty() {
        None
    } else {
        Some(
            revoked_serials
                .iter()
                .map(|serial| RevokedCert {
                    serial_number: serial.clone(),
                    revocation_date: this_update,
                    crl_entry_extensions: None,
                })
                .collect(),
        )
    };

    let tbs = TbsCertList {
        version: Version::V2,
        signature: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        issuer,
        this_update,
        next_update: Some(next_update),
        revoked_certificates,
        crl_extensions: Some(build_crl_extensions(root_cert)),
    };

    let tbs_bytes = tbs.to_der().unwrap();
    let signature: ecdsa::Signature<NistP256> = root_key.sign(&tbs_bytes);

    CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
        signature: signature.to_der().to_bitstring().unwrap(),
    }
    .to_der()
    .unwrap()
}

/// Setup test certificates with a custom CRL URL.
/// Returns (root_cert, signer_cert, root_key, issuer_name).
pub(crate) fn setup_with_crl_url(
    crl_url: String,
) -> (Certificate, Certificate, p256::ecdsa::SigningKey, Name) {
    let pki = TestPki::generate(crl_url, default_validity(), EKU_MDOC_DS);
    (pki.root, pki.leaf, pki.root_key, pki.issuer)
}

mod iaca {
    use der::EncodePem;

    use super::{default_validity, ObjectIdentifier, TestPki};
    use crate::definitions::x509::{
        trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose},
        validation::{validate, EuAgeVerificationProfile},
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
        let outcome = validate(
            &crate::definitions::x509::validation::MdocProfile::MDL.issuer,
            &x5chain,
            &trust_anchor_registry,
            &(),
        )
        .await;
        assert!(outcome.success(), "{outcome:?}");
    }

    /// The EU age verification PKI, as a worked example of [`CertificateProfile`].
    ///
    /// `eu.europa.ec.av.1` defines no mdoc key-purpose OIDs at all. Its architecture wants a
    /// document signer "compliant with ETSI EN 319 411-1 NCP policy", trusted through an
    /// EC-managed ETSI TS 119 612 Trusted List rather than an IACA root, and ETSI PKIs put
    /// intermediate CAs between signer and root. None of that is an OID value, so no
    /// [`MdocProfile`] constant can express it — which is the case the trait exists for.
    ///
    /// This is what a consumer writes for a credential we do not ship a profile for.
    ///
    /// [`CertificateProfile`]: crate::definitions::x509::validation::CertificateProfile
    #[test_log::test(tokio::test)]
    async fn a_custom_profile_can_express_eu_age_verification() {
        let etsi = TestPki::etsi_av();
        let outcome = validate(
            &EuAgeVerificationProfile,
            &etsi.x5chain(),
            &etsi.registry(TrustPurpose::Iaca),
            &(),
        )
        .await;
        assert!(outcome.success(), "{outcome:?}");

        // The policy check has teeth, and tells its two failure modes apart. An mDL signer
        // carries no certificate policies at all...
        let mdl = TestPki::generate(
            TestPki::CRL_URL.to_string(),
            default_validity(),
            crate::definitions::x509::validation::MdocProfile::MDL
                .issuer
                .document_signer_eku,
        );
        let outcome = validate(
            &EuAgeVerificationProfile,
            &mdl.x5chain(),
            &mdl.registry(TrustPurpose::Iaca),
            &(),
        )
        .await;
        assert!(
            outcome
                .errors
                .iter()
                .any(|e| e.contains("certificatepolicies: required extension not found")),
            "{outcome:?}"
        );

        // ...whereas a signer asserting some *other* policy is a different diagnosis.
        let wrong_policy =
            TestPki::etsi_av_with_policy(ObjectIdentifier::new_unwrap("0.4.0.2042.1.2"));
        let outcome = validate(
            &EuAgeVerificationProfile,
            &wrong_policy.x5chain(),
            &wrong_policy.registry(TrustPurpose::Iaca),
            &(),
        )
        .await;
        assert!(
            outcome
                .errors
                .iter()
                .any(|e| e.contains("does not assert the ETSI NCP policy")),
            "{outcome:?}"
        );
    }

    /// The shipped profiles must keep rejecting an ETSI-shaped signer.
    ///
    /// Age verification is supported by writing a profile, not by loosening the mdoc ones:
    /// none of these should ever accept a certificate carrying no mdoc key purpose.
    #[test_log::test(tokio::test)]
    async fn the_shipped_profiles_reject_an_etsi_signer() {
        use crate::definitions::x509::validation::MdocProfile;

        let pki = TestPki::etsi_av();
        let registry = pki.registry(TrustPurpose::Iaca);

        for (name, profile) in [
            ("MDL", MdocProfile::MDL),
            ("AAMVA_MDL", MdocProfile::AAMVA_MDL),
            ("ISO_23220", MdocProfile::ISO_23220),
            ("EUDI_PID", MdocProfile::EUDI_PID),
        ] {
            let outcome = validate(&profile.issuer, &pki.x5chain(), &registry, &()).await;
            let joined = outcome.errors.join("; ").to_lowercase();
            assert!(
                joined.contains("extendedkeyusage: required extension not found"),
                "{name} should reject a signer with no mdoc key purpose, got {joined}"
            );
        }
    }

    /// ISO/IEC TS 23220-4 B.2.5 mandates no extensions beyond the key purposes, and the
    /// Annex C photo ID profile puts revocation out of scope. Requiring
    /// `cRLDistributionPoints` and `issuerAlternativeName` — as Annex B does — would reject
    /// a conformant photo ID.
    #[test_log::test(tokio::test)]
    async fn iso_23220_accepts_a_signer_without_crl_or_issuer_alt_name() {
        use crate::definitions::x509::validation::MdocProfile;

        let pki = TestPki::etsi_av();
        let registry = pki.registry(TrustPurpose::Iaca);

        let joined = validate(
            &MdocProfile::ISO_23220.issuer,
            &pki.x5chain(),
            &registry,
            &(),
        )
        .await
        .errors
        .join("; ")
        .to_lowercase();

        for absent in ["crldistributionpoints", "issueralternativename"] {
            assert!(
                !joined.contains(absent),
                "ISO_23220 should not require {absent}, got {joined}"
            );
        }
        // Whereas Annex B does require both.
        let joined = validate(&MdocProfile::MDL.issuer, &pki.x5chain(), &registry, &())
            .await
            .errors
            .join("; ")
            .to_lowercase();
        for required in ["crldistributionpoints", "issueralternativename"] {
            assert!(
                joined.contains(&format!("{required}: required extension not found")),
                "MDL should require {required}, got {joined}"
            );
        }
    }

    /// ISO/IEC 18013-5 Annex B requires the document signer and the IACA root to carry the
    /// same `countryName`. Unlike `stateOrProvinceName` this is not configurable — no
    /// profile may switch it off — so it is checked for every issuer profile.
    #[test_log::test(tokio::test)]
    async fn a_document_signer_must_share_its_root_country() {
        use crate::definitions::x509::validation::MdocProfile;

        let pki = TestPki::generate_with_signer_subject(
            TestPki::CRL_URL.to_string(),
            default_validity(),
            MdocProfile::MDL.issuer.document_signer_eku,
            "CN=subject,C=DE",
        );

        let outcome = validate(
            &MdocProfile::MDL.issuer,
            &pki.x5chain(),
            &pki.registry(TrustPurpose::Iaca),
            &(),
        )
        .await;

        // `c` is the short name `countryName` is registered under.
        assert!(
            outcome
                .errors
                .iter()
                .any(|e| e.contains("subject 'c' does not match: DE != US")),
            "a DE signer under a US root should be rejected, got {outcome:?}"
        );
    }

    /// AAMVA requires the document signer and root to agree on `stateOrProvinceName`
    /// even when neither carries it; ISO/IEC 18013-5 only compares when one does.
    ///
    /// The test certificates carry no `stateOrProvinceName`, so the two rules disagree
    /// about them — which is what makes this able to tell them apart at all.
    #[test_log::test(tokio::test)]
    async fn aamva_requires_a_state_or_province_iso_does_not() {
        use crate::definitions::x509::validation::MdocProfile;

        let pki = TestPki::issuer();
        let registry = pki.registry(TrustPurpose::Iaca);

        let iso = validate(&MdocProfile::MDL.issuer, &pki.x5chain(), &registry, &()).await;
        assert!(iso.success(), "{iso:?}");

        let aamva = validate(
            &MdocProfile::AAMVA_MDL.issuer,
            &pki.x5chain(),
            &registry,
            &(),
        )
        .await;
        assert!(
            aamva
                .errors
                .iter()
                .any(|e| e.to_string().contains("stateOrProvinceName")),
            "{aamva:?}"
        );
    }
}
