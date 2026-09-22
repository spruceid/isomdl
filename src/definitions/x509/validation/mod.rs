use const_oid::db::rfc2256::STATE_OR_PROVINCE_NAME;
use error::ErrorWithContext;
use extensions::{
    key_identifier_check, validate_document_signer_certificate_extensions,
    validate_iaca_extensions, validate_mdoc_reader_certificate_extensions,
    validate_vical_signer_certificate_extensions,
};
use names::{country_name_matches, has_rdn, state_or_province_name_matches};
use serde::{Deserialize, Serialize};
use signature::issuer_signed_subject;
use time::OffsetDateTime;
use validity::check_validity_period_at;
use x509_cert::Certificate;

use super::{
    revocation::{check_certificate_revocation, RevocationFetcher, RevocationStatus},
    trust_anchor::{TrustAnchorRegistry, TrustPurpose},
    util::common_name_or_unknown,
    X5Chain,
};

mod error;
mod eu_age_verification;
mod extensions;
mod names;
pub(super) mod signature;
mod validity;

/// Options for certificate chain validation.
///
/// This struct is intentionally limited to parameters that have safe defaults
/// and are only tweaked in specific scenarios (e.g., testing with a pinned time).
/// Parameters like [`TrustAnchorRegistry`] and [`RevocationFetcher`]
/// are kept as explicit function arguments because they require deliberate choices:
/// you should always think carefully about which roots you trust and which HTTP
/// client is appropriate for your platform.
#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    /// The time to use for validity period checks.
    /// If `None`, the current system time is used.
    pub validation_time: Option<OffsetDateTime>,
}

impl ValidationOptions {
    /// Get the validation time, defaulting to current time if not set.
    pub(crate) fn validation_time(&self) -> OffsetDateTime {
        self.validation_time.unwrap_or_else(OffsetDateTime::now_utc)
    }
}

pub use eu_age_verification::{
    EuAgeVerificationProfile, EU_AGE_VERIFICATION_DOC_TYPE, NCP_POLICY_OID,
};

/// Re-exported so the profile types' public fields can be named without taking a
/// version-matched `const-oid` dependency.
pub use const_oid::ObjectIdentifier;

/// The document-type-specific parameters of the ISO/IEC 18013-5 Annex B certificate profile.
///
/// Annex B's *structure* is credential-agnostic — IACA root, no sub-CAs, subject key
/// identifier, key usage, mandatory CRL distribution points, issuer alternative name, DER
/// encoding, matching country codes. What is mDL-specific is the OID values: Annex B's own
/// table labels `1.0.18013.5.1.2` as "reserved for **mDL** DS", and other credentials
/// define their own on their own arc. ISO/IEC DIS 18013-5 says so outright — Annex B does
/// not apply when reading other mdoc based documents.
///
/// [`MDL`](Self::MDL), [`AAMVA_MDL`](Self::AAMVA_MDL), [`ISO_23220`](Self::ISO_23220) and
/// [`EUDI_PID`](Self::EUDI_PID) are shipped. Anything else takes its OIDs from the profile
/// you are implementing: guessing one would silently accept or reject the wrong
/// certificates. A credential whose PKI differs by more than its OIDs — a chain with
/// intermediate CAs, or certificates carrying no mdoc key purpose — needs a
/// [`CertificateProfile`] implementation instead.
///
/// The two halves are separate because they are consumed separately: issuing a document and
/// reading one are validated by different code paths, against different trust anchors, and a
/// rule that belongs to one is meaningless to the other.
///
/// ```
/// use isomdl::definitions::x509::validation::{IssuerProfile, MdocProfile, ObjectIdentifier};
///
/// let profile = MdocProfile {
///     issuer: IssuerProfile {
///         document_signer_eku: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.2"),
///         ..MdocProfile::MDL.issuer
///     },
///     ..MdocProfile::MDL
/// };
/// assert_ne!(profile, MdocProfile::MDL);
/// assert_ne!(MdocProfile::ISO_23220, MdocProfile::MDL);
/// ```
/// The two halves are generic so a custom [`CertificateProfile`] can take either place.
/// The shipped constants are the default instantiation,
/// `MdocProfile<IssuerProfile, ReaderProfile>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdocProfile<I = IssuerProfile, R = ReaderProfile> {
    /// Rules for a document signer certificate, applied when reading a document.
    pub issuer: I,
    /// Rules for a reader certificate, applied when a device authenticates a request.
    pub reader: R,
}

/// The document signer half of an [`MdocProfile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerProfile {
    /// The `extendedKeyUsage` OID the document signer certificate must carry.
    ///
    /// The check requires the certificate's EKU to contain *only* this OID, so a
    /// dual-purpose signer listing several fails.
    #[serde(with = "oid_as_string")]
    pub document_signer_eku: ObjectIdentifier,
    /// How the document signer's and root's `stateOrProvinceName` are compared.
    pub state_or_province: RdnRule,
    /// Whether `cRLDistributionPoints` is mandatory.
    ///
    /// Defaulted so a profile document written before this field existed still loads, and
    /// loads as Annex B rather than as the laxer rule.
    #[serde(default)]
    pub crl_distribution_points: ExtensionRule,
    /// Whether `issuerAlternativeName` is mandatory. Defaulted, as above.
    #[serde(default)]
    pub issuer_alternative_name: ExtensionRule,
}

/// The reader half of an [`MdocProfile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderProfile {
    /// The `extendedKeyUsage` OID a reader certificate must carry.
    #[serde(with = "oid_as_string")]
    pub reader_auth_eku: ObjectIdentifier,
    /// Whether `cRLDistributionPoints` is mandatory.
    ///
    /// Defaulted so a profile document written before this field existed still loads, and
    /// loads as Annex B rather than as the laxer rule.
    #[serde(default)]
    pub crl_distribution_points: ExtensionRule,
    /// Whether `issuerAlternativeName` is mandatory. Defaulted, as above.
    #[serde(default)]
    pub issuer_alternative_name: ExtensionRule,
}

/// Whether a certificate profile mandates an extension.
///
/// [`Optional`](Self::Optional) only relaxes the requirement to carry the extension. One that
/// is present is validated either way, so relaxing a profile never skips a check on data that
/// is actually there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRule {
    /// The certificate must carry the extension. This is the ISO/IEC 18013-5 Annex B rule
    /// for `cRLDistributionPoints` and `issuerAlternativeName`, and the default a profile
    /// deserialized from a document that predates these fields takes.
    #[default]
    Required,
    /// The certificate may omit the extension.
    Optional,
}

/// How a relative distinguished name is compared between a certificate and its root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RdnRule {
    /// Compare only when at least one of the two carries the attribute, as ISO/IEC 18013-5
    /// requires. Absent from both is conformant.
    MatchIfPresent,
    /// Compare unconditionally, which also fails when the attribute is absent. AAMVA
    /// requires this of `stateOrProvinceName`.
    Required,
}

impl MdocProfile {
    /// The mDL profile defined by ISO/IEC 18013-5 Annex B.
    pub const MDL: Self = Self {
        issuer: IssuerProfile {
            document_signer_eku: extensions::document_signer_extended_key_usage_oid(),
            state_or_province: RdnRule::MatchIfPresent,
            crl_distribution_points: ExtensionRule::Required,
            issuer_alternative_name: ExtensionRule::Required,
        },
        reader: ReaderProfile {
            reader_auth_eku: extensions::mdoc_reader_extended_key_usage_oid(),
            crl_distribution_points: ExtensionRule::Required,
            issuer_alternative_name: ExtensionRule::Required,
        },
    };

    /// [`MDL`](Self::MDL) with AAMVA's stricter `stateOrProvinceName` rule.
    pub const AAMVA_MDL: Self = Self {
        issuer: IssuerProfile {
            state_or_province: RdnRule::Required,
            ..Self::MDL.issuer
        },
        ..Self::MDL
    };

    /// The EUDI Person Identification Data profile, from the PID Rulebook of the European
    /// Digital Identity Wallet Architecture and Reference Framework.
    ///
    /// The rulebook defines its key purposes by ASN.1 rather than by value:
    ///
    /// ```text
    /// id-eudi                       ::= { european-commission 2 }   -- 1.3.130.2
    /// id-eudi-iso                   ::= { id-eudi 0 }
    /// id-eudi-iso-pid               ::= { id-eudi-iso 0 }
    /// id-eudi-iso-pid-kp            ::= { id-eudi-iso-pid 1 }
    /// id-eudi-iso-pid-kp-DS         ::= { id-eudi-iso-pid-kp 2 }    -- 1.3.130.2.0.0.1.2
    /// id-eudi-iso-pid-kp-ReaderAuth ::= { id-eudi-iso-pid-kp 6 }    -- 1.3.130.2.0.0.1.6
    /// ```
    ///
    /// `1.3.130` is the registered European Commission arc, so the values follow from the
    /// ASN.1 without guesswork. **The assignments below it are not yet registered** — the
    /// rulebook says these OIDs "will have to be officially registered" — so treat this
    /// constant as provisional and check it against the rulebook edition you target.
    ///
    /// The rulebook specifies no rule that differs from ISO/IEC 18013-5 Annex B: the OIDs
    /// are used "in exactly the same way as the corresponding OIDs specified in
    /// ISO/IEC 18013-5". So this is [`MDL`](Self::MDL) rebased, exactly as
    /// [`ISO_23220`](Self::ISO_23220) is.
    pub const EUDI_PID: Self = Self {
        issuer: IssuerProfile {
            document_signer_eku: ObjectIdentifier::new_unwrap("1.3.130.2.0.0.1.2"),
            ..Self::MDL.issuer
        },
        reader: ReaderProfile {
            reader_auth_eku: ObjectIdentifier::new_unwrap("1.3.130.2.0.0.1.6"),
            ..Self::MDL.reader
        },
    };

    /// The generic mdoc key purposes of ISO/IEC TS 23220-4:2026, Annex B.2.5.
    ///
    /// `id-mdoc ::= { iso(1) standard(0) 23220 4 }` numbers its key purposes exactly as
    /// ISO/IEC 18013-5 does — document signer at `2`, reader authentication at `6` — so
    /// this is [`MDL`](Self::MDL) rebased onto the credential-agnostic arc.
    ///
    /// 23220-4 says a conformant profile *may* use these, not that it must, so a
    /// credential built on 23220 can still define its own. Check the profile you are
    /// implementing rather than assuming this one.
    /// `cRLDistributionPoints` and `issuerAlternativeName` are optional here, unlike in
    /// [`MDL`](Self::MDL): B.2.5 mandates no extensions beyond the key purposes, and the
    /// photo ID profile of Annex C puts revocation out of scope. Requiring them would
    /// reject a conformant credential.
    pub const ISO_23220: Self = Self {
        issuer: IssuerProfile {
            document_signer_eku: ObjectIdentifier::new_unwrap("1.0.23220.4.1.2"),
            crl_distribution_points: ExtensionRule::Optional,
            issuer_alternative_name: ExtensionRule::Optional,
            ..Self::MDL.issuer
        },
        reader: ReaderProfile {
            reader_auth_eku: ObjectIdentifier::new_unwrap("1.0.23220.4.1.6"),
            crl_distribution_points: ExtensionRule::Optional,
            issuer_alternative_name: ExtensionRule::Optional,
        },
    };
}

impl Default for MdocProfile {
    fn default() -> Self {
        Self::MDL
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ValidationOutcome {
    pub errors: Vec<String>,
    /// Errors encountered while checking CRL revocation status (e.g., fetch failures,
    /// parse errors, missing distribution points).
    ///
    /// These are kept separate from `errors` because they represent infrastructure
    /// failures rather than security failures. Actual certificate revocation is
    /// reported in `errors`, not here.
    pub revocation_errors: Vec<String>,
}

impl ValidationOutcome {
    pub fn success(&self) -> bool {
        self.errors.is_empty()
    }
}

/// `const_oid::ObjectIdentifier` has no serde impls in the version this crate pins (0.9 has
/// no `serde` feature at all), so OIDs travel as dotted-decimal strings — the form a profile
/// document quotes them in.
mod oid_as_string {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    use super::ObjectIdentifier;

    pub fn serialize<S: Serializer>(oid: &ObjectIdentifier, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(oid)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ObjectIdentifier, D::Error> {
        let dotted = String::deserialize(d)?;
        ObjectIdentifier::new(&dotted).map_err(D::Error::custom)
    }
}

/// How a certificate chain is validated against a trust anchor registry.
///
/// The built-in profiles — [`IssuerProfile`], [`ReaderProfile`] and [`VicalProfile`] — cover
/// ISO/IEC 18013-5 and the credentials that rebase it onto their own OID arc. Implement
/// this trait for a
/// credential whose PKI differs in ways an [`MdocProfile`] cannot express: a chain carrying
/// intermediate CA certificates, certificates carrying no mdoc key purpose at all, or checks
/// this library does not know about.
///
/// Every rule is a required method. There is no Annex B default to inherit, because there is
/// no rule common to all mdoc PKIs — age verification shares none of Annex B's. A profile
/// states each axis explicitly, including the ones where it constrains nothing, so a rule
/// never applies because an implementor did not know it was there.
///
/// To reuse a shipped rule rather than restate it, delegate to the built-in that carries it:
/// `MdocProfile::MDL.issuer.validate_trust_anchor(certificate)`.
pub trait CertificateProfile {
    /// Checks applied to the end-entity certificate — document signer, reader, or VICAL
    /// signer, depending on the profile.
    fn validate_end_entity(&self, certificate: &Certificate) -> Vec<String>;

    /// Which trust anchors may terminate the chain.
    fn trust_purpose(&self) -> TrustPurpose;

    /// Checks applied to the trust anchor the chain terminates at. Return an empty `Vec` to
    /// state that a profile does not constrain its anchor.
    fn validate_trust_anchor(&self, certificate: &Certificate) -> Vec<String>;

    /// Checks comparing the end-entity certificate against its trust anchor, such as the
    /// matching country codes ISO/IEC 18013-5 Annex B requires.
    fn validate_against_trust_anchor(
        &self,
        end_entity: &Certificate,
        trust_anchor: &Certificate,
    ) -> Vec<String>;

    /// Whether intermediate CA certificates may sit between the end-entity certificate and
    /// the trust anchor. ISO/IEC 18013-5 Annex B forbids sub-CAs.
    fn chain(&self) -> ChainRule;

    /// Where this PKI publishes revocation.
    fn revocation(&self) -> RevocationRule;

    /// How the end-entity certificate is named in error messages. A label, not a rule, so
    /// this one is defaulted.
    fn end_entity_name(&self) -> &'static str {
        "End-entity certificate"
    }

    /// How the trust anchor is named in error messages. A label, not a rule.
    fn trust_anchor_name(&self) -> &'static str {
        "Trust anchor certificate"
    }
}

/// Where a profile's revocation status is published.
///
/// Distinct from the [`RevocationFetcher`] argument, which says *how* to fetch a CRL: this
/// says whether there is one to fetch. A deployment passing `&()` has declined to check
/// revocation it could have checked; a profile answering [`OutOfBand`](Self::OutOfBand) is
/// stating that this PKI does not publish it here at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationRule {
    /// Certificates carry `cRLDistributionPoints`, and are checked against the CRL found
    /// there. ISO/IEC 18013-5 Annex B requires the extension.
    Crl,
    /// Revocation is published somewhere this library does not read — an ETSI Trusted List,
    /// a status list. No CRL is fetched, and a warning records that revocation was not
    /// checked here, so "not checked" never reads as "checked and clean".
    OutOfBand,
}

/// Whether a profile permits intermediate CA certificates in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainRule {
    /// Only the first certificate of the chain is used, and the trust anchor must be its
    /// direct issuer. ISO/IEC 18013-5 Annex B, NOTE 1 in B.1.1.
    EndEntityOnly,
    /// The chain is walked from end-entity towards root, verifying each link, until a
    /// certificate in it is a trust anchor or a trust anchor signs its last certificate.
    WalkToTrustAnchor,
}

impl CertificateProfile for IssuerProfile {
    fn validate_end_entity(&self, certificate: &Certificate) -> Vec<String> {
        validate_document_signer_certificate_extensions(
            certificate,
            self.document_signer_eku,
            self.crl_distribution_points,
            self.issuer_alternative_name,
        )
    }

    fn trust_purpose(&self) -> TrustPurpose {
        TrustPurpose::Iaca
    }

    fn validate_trust_anchor(&self, certificate: &Certificate) -> Vec<String> {
        validate_iaca_extensions(certificate)
    }

    /// Annex B forbids sub-CAs.
    fn chain(&self) -> ChainRule {
        ChainRule::EndEntityOnly
    }

    /// Annex B requires `cRLDistributionPoints` on the document signer.
    fn revocation(&self) -> RevocationRule {
        RevocationRule::Crl
    }

    fn validate_against_trust_anchor(
        &self,
        document_signer: &Certificate,
        iaca: &Certificate,
    ) -> Vec<String> {
        let mut errors: Vec<String> = country_name_matches(document_signer, iaca)
            .into_iter()
            .map(|e| e.to_string())
            .collect();

        // 18013-5 only compares the field when one of the two carries it; AAMVA
        // requires the comparison unconditionally, which also fails when it is absent.
        let compare = self.state_or_province == RdnRule::Required
            || has_rdn(document_signer, STATE_OR_PROVINCE_NAME)
            || has_rdn(iaca, STATE_OR_PROVINCE_NAME);
        if compare {
            errors.extend(
                state_or_province_name_matches(document_signer, iaca).map(|e| e.to_string()),
            );
        }

        errors
    }

    fn end_entity_name(&self) -> &'static str {
        "DS certificate"
    }

    fn trust_anchor_name(&self) -> &'static str {
        "IACA certificate"
    }
}

impl CertificateProfile for ReaderProfile {
    fn validate_end_entity(&self, certificate: &Certificate) -> Vec<String> {
        validate_mdoc_reader_certificate_extensions(
            certificate,
            self.reader_auth_eku,
            self.crl_distribution_points,
            self.issuer_alternative_name,
        )
    }

    fn trust_purpose(&self) -> TrustPurpose {
        TrustPurpose::ReaderCa
    }

    /// ISO/IEC 18013-5 Annex B gives no reader CA extension table, so the anchor is
    /// accepted on its registration alone.
    fn validate_trust_anchor(&self, _certificate: &Certificate) -> Vec<String> {
        Vec::new()
    }

    /// Annex B constrains no name shared between a reader certificate and its CA.
    fn validate_against_trust_anchor(
        &self,
        _reader: &Certificate,
        _reader_ca: &Certificate,
    ) -> Vec<String> {
        Vec::new()
    }

    /// Annex B forbids sub-CAs.
    fn chain(&self) -> ChainRule {
        ChainRule::EndEntityOnly
    }

    /// Annex B requires `cRLDistributionPoints` on the reader certificate.
    fn revocation(&self) -> RevocationRule {
        RevocationRule::Crl
    }

    fn end_entity_name(&self) -> &'static str {
        "Reader certificate"
    }

    fn trust_anchor_name(&self) -> &'static str {
        "Reader CA certificate"
    }
}

/// The VICAL signer profile of ISO/IEC 18013-5 Annex C.
///
/// Unlike the document profiles this walks the whole chain, which may carry intermediate CA
/// certificates, to a [`TrustPurpose::VicalAuthority`] anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VicalProfile;

impl CertificateProfile for VicalProfile {
    fn validate_end_entity(&self, certificate: &Certificate) -> Vec<String> {
        validate_vical_signer_certificate_extensions(certificate)
    }

    fn trust_purpose(&self) -> TrustPurpose {
        TrustPurpose::VicalAuthority
    }

    /// Annex C gives no VICAL authority extension table.
    fn validate_trust_anchor(&self, _certificate: &Certificate) -> Vec<String> {
        Vec::new()
    }

    /// Annex C constrains no name shared between a VICAL signer and its authority.
    fn validate_against_trust_anchor(
        &self,
        _signer: &Certificate,
        _authority: &Certificate,
    ) -> Vec<String> {
        Vec::new()
    }

    fn chain(&self) -> ChainRule {
        ChainRule::WalkToTrustAnchor
    }

    fn revocation(&self) -> RevocationRule {
        RevocationRule::Crl
    }

    fn end_entity_name(&self) -> &'static str {
        "VICAL signer certificate"
    }

    fn trust_anchor_name(&self) -> &'static str {
        "VICAL authority certificate"
    }
}

/// Validate a certificate chain under `profile`, with default options.
///
/// # Arguments
/// * `profile` - The certificate profile to validate under, such as
///   [`MdocProfile::MDL`]`.issuer` or [`VicalProfile`].
/// * `x5chain` - The certificate chain to validate
/// * `trust_anchors` - The trust anchor registry
/// * `revocation_fetcher` - Revocation fetcher for CRL checking. Use `&()` to skip revocation
///   checks (a warning will be added to `revocation_errors`).
pub async fn validate<P: CertificateProfile, R: RevocationFetcher>(
    profile: &P,
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    revocation_fetcher: &R,
) -> ValidationOutcome {
    validate_with_options(
        profile,
        x5chain,
        trust_anchors,
        revocation_fetcher,
        &ValidationOptions::default(),
    )
    .await
}

/// Validate a certificate chain under `profile`, with custom options.
pub async fn validate_with_options<P: CertificateProfile, R: RevocationFetcher>(
    profile: &P,
    x5chain: &X5Chain,
    trust_anchors: &TrustAnchorRegistry,
    revocation_fetcher: &R,
    options: &ValidationOptions,
) -> ValidationOutcome {
    let mut outcome = ValidationOutcome::default();
    let validation_time = options.validation_time();
    let end_entity_name = profile.end_entity_name();
    let end_entity = x5chain.end_entity_certificate();

    outcome.errors.extend(
        check_validity_period_at(end_entity, validation_time)
            .into_iter()
            .map(|e| ErrorWithContext::labelled(end_entity_name, e)),
    );

    outcome.errors.extend(
        profile
            .validate_end_entity(end_entity)
            .into_iter()
            .map(|e| ErrorWithContext::labelled(end_entity_name, e)),
    );

    match profile.chain() {
        ChainRule::EndEntityOnly => {
            let mut candidates = find_trust_anchor_candidates(
                end_entity,
                trust_anchors,
                profile.trust_purpose(),
                validation_time,
            );

            let Some(anchor) = candidates.next() else {
                outcome.errors.push(ErrorWithContext::labelled(
                    profile.trust_anchor_name(),
                    "no valid trust anchor found",
                ));
                return outcome;
            };

            if candidates.next().is_some() {
                tracing::warn!("more than one trust anchor candidate found, using the first one");
            }

            check_anchor(&mut outcome, profile, end_entity, anchor);

            match profile.revocation() {
                RevocationRule::Crl => {
                    check_revocation(
                        &mut outcome,
                        revocation_fetcher,
                        end_entity,
                        anchor,
                        options,
                        end_entity_name,
                    )
                    .await;
                }
                RevocationRule::OutOfBand => note_out_of_band_revocation(&mut outcome, profile),
            }
        }
        ChainRule::WalkToTrustAnchor => {
            let chain_result = validate_chain_to_trust_anchor(
                x5chain,
                trust_anchors,
                profile.trust_purpose(),
                &mut outcome,
                validation_time,
            );

            let external_trust_anchor = match chain_result {
                ChainToTrustAnchorResult::ValidInChainAnchor(anchor) => {
                    check_anchor(&mut outcome, profile, end_entity, anchor);
                    None
                }
                ChainToTrustAnchorResult::ValidExternalAnchor(anchor) => {
                    check_anchor(&mut outcome, profile, end_entity, anchor);
                    Some(anchor)
                }
                ChainToTrustAnchorResult::Invalid => {
                    outcome.errors.push(ErrorWithContext::labelled(
                        profile.trust_anchor_name(),
                        "no valid trust anchor found for certificate chain",
                    ));
                    None
                }
            };

            match profile.revocation() {
                RevocationRule::Crl => {
                    let certificates: Vec<_> = x5chain.iter().collect();
                    for window in certificates.windows(2) {
                        check_chain_link_revocation(
                            &mut outcome,
                            revocation_fetcher,
                            &window[0].inner,
                            &window[1].inner,
                            options,
                        )
                        .await;
                    }

                    if let Some(trust_anchor) = external_trust_anchor {
                        check_chain_link_revocation(
                            &mut outcome,
                            revocation_fetcher,
                            x5chain.root_entity_certificate(),
                            trust_anchor,
                            options,
                        )
                        .await;
                    }
                }
                RevocationRule::OutOfBand => note_out_of_band_revocation(&mut outcome, profile),
            }
        }
    }

    outcome
}

fn check_anchor<P: CertificateProfile>(
    outcome: &mut ValidationOutcome,
    profile: &P,
    end_entity: &Certificate,
    anchor: &Certificate,
) {
    let anchor_name = profile.trust_anchor_name();

    outcome.errors.extend(
        profile
            .validate_trust_anchor(anchor)
            .into_iter()
            .map(|e| ErrorWithContext::labelled(anchor_name, e)),
    );

    outcome.errors.extend(
        profile
            .validate_against_trust_anchor(end_entity, anchor)
            .into_iter()
            .map(ErrorWithContext::comparison),
    );
}

/// Record that this profile publishes revocation somewhere the library does not read.
///
/// A warning rather than nothing: the caller has to know revocation was not checked here,
/// or it will read a clean outcome as "not revoked".
fn note_out_of_band_revocation<P: CertificateProfile>(
    outcome: &mut ValidationOutcome,
    profile: &P,
) {
    outcome.revocation_errors.push(ErrorWithContext::labelled(
        profile.end_entity_name(),
        "revocation is published out of band for this profile and was not checked here",
    ));
}

async fn check_revocation<R: RevocationFetcher>(
    outcome: &mut ValidationOutcome,
    revocation_fetcher: &R,
    subject: &Certificate,
    issuer: &Certificate,
    options: &ValidationOptions,
    subject_name: &'static str,
) {
    match check_certificate_revocation(revocation_fetcher, subject, issuer, options).await {
        Ok(RevocationStatus::Valid) => {}
        Ok(RevocationStatus::Revoked { .. }) => {
            // Actual revocation is a hard security failure
            outcome.errors.push(ErrorWithContext::labelled(
                subject_name,
                "certificate is revoked",
            ));
        }
        Err(e) => {
            // Infrastructure failures are non-fatal warnings
            outcome
                .revocation_errors
                .push(ErrorWithContext::labelled(subject_name, e.to_string()));
        }
    }
}

async fn check_chain_link_revocation<R: RevocationFetcher>(
    outcome: &mut ValidationOutcome,
    revocation_fetcher: &R,
    subject: &Certificate,
    issuer: &Certificate,
    options: &ValidationOptions,
) {
    match check_certificate_revocation(revocation_fetcher, subject, issuer, options).await {
        Ok(RevocationStatus::Valid) => {}
        Ok(RevocationStatus::Revoked { .. }) => {
            outcome.errors.push(ErrorWithContext::chain(format!(
                "certificate '{}' is revoked",
                common_name_or_unknown(subject)
            )));
        }
        Err(e) => {
            outcome
                .revocation_errors
                .push(ErrorWithContext::chain(format!(
                    "CRL check for '{}': {}",
                    common_name_or_unknown(subject),
                    e
                )));
        }
    }
}

/// Result of validating a certificate chain to a trust anchor.
enum ChainToTrustAnchorResult<'a> {
    /// Chain is valid and the trust anchor is within the chain itself.
    /// No external issuer certificate is available for CRL checking the last cert.
    ValidInChainAnchor(&'a Certificate),
    /// Chain is valid and signed by an external trust anchor (not in the chain).
    /// The trust anchor certificate is returned for CRL checking the last cert.
    ValidExternalAnchor(&'a Certificate),
    /// Chain is invalid - no valid trust anchor found or signature verification failed.
    /// Errors have been recorded in the outcome.
    Invalid,
}

/// Validate that the certificate chain terminates at a trust anchor.
///
/// Walks the chain from end-entity towards root, verifying signatures and checking
/// if any certificate is a trust anchor or if a trust anchor signs the last certificate.
///
/// Any validation errors (signature failures, validity issues) are recorded in `outcome`.
fn validate_chain_to_trust_anchor<'a>(
    x5chain: &'a X5Chain,
    trust_anchors: &'a TrustAnchorRegistry,
    trust_purpose: TrustPurpose,
    outcome: &mut ValidationOutcome,
    validation_time: OffsetDateTime,
) -> ChainToTrustAnchorResult<'a> {
    let certificates: Vec<_> = x5chain.iter().collect();

    // Walk the chain from end-entity towards root, verifying each signature.
    for (i, window) in certificates.windows(2).enumerate() {
        let subject = &window[0].inner;
        let issuer = &window[1].inner;

        // Verify the chain link signature first.
        if !issuer_signed_subject(subject, issuer) {
            outcome.errors.push(ErrorWithContext::chain(format!(
                "certificate '{}' not signed by '{}'",
                common_name_or_unknown(subject),
                common_name_or_unknown(issuer)
            )));
            return ChainToTrustAnchorResult::Invalid;
        }

        // Check validity of intermediate certificates.
        let validity_errors = check_validity_period_at(issuer, validation_time);
        if !validity_errors.is_empty() {
            outcome
                .errors
                .extend(validity_errors.into_iter().map(ErrorWithContext::chain));
        }

        // Check if the issuer (next cert in chain) is a trust anchor.
        // This handles chains like [signer, intermediate] where we trust the intermediate.
        if is_trusted_certificate(issuer, trust_anchors, trust_purpose, validation_time) {
            tracing::debug!(
                "chain terminates at trust anchor at position {} ({})",
                i + 1,
                common_name_or_unknown(issuer)
            );
            return ChainToTrustAnchorResult::ValidInChainAnchor(issuer);
        }
    }

    // Check if the last certificate in the chain is a trust anchor (self-signed root in chain).
    let last_cert = x5chain.root_entity_certificate();
    if is_trusted_certificate(last_cert, trust_anchors, trust_purpose, validation_time) {
        tracing::debug!(
            "chain terminates at trust anchor (last cert): {}",
            common_name_or_unknown(last_cert)
        );
        return ChainToTrustAnchorResult::ValidInChainAnchor(last_cert);
    }

    // Finally, check if a trust anchor signed the last certificate in the chain.
    // This uses the same matching logic as mDL validation (key identifier + signature).
    let mut trust_anchor_candidates =
        find_trust_anchor_candidates(last_cert, trust_anchors, trust_purpose, validation_time);

    if let Some(trust_anchor) = trust_anchor_candidates.next() {
        tracing::debug!(
            "chain terminates with external trust anchor signing last cert: {}",
            common_name_or_unknown(last_cert)
        );
        return ChainToTrustAnchorResult::ValidExternalAnchor(trust_anchor);
    }

    ChainToTrustAnchorResult::Invalid
}

/// Check if a certificate directly matches a trust anchor.
///
/// This is used when the trust anchor certificate itself is included in the chain,
/// rather than being an external issuer. We match by subject name and public key
/// (SPKI), which is more reliable than key identifiers alone since it ensures the
/// actual keys are identical.
fn is_trusted_certificate(
    certificate: &Certificate,
    trust_anchors: &TrustAnchorRegistry,
    trust_purpose: TrustPurpose,
    validation_time: OffsetDateTime,
) -> bool {
    trust_anchors
        .anchors
        .iter()
        .filter(|anchor| anchor.purpose == trust_purpose)
        // Filter out expired trust anchors, consistent with find_trust_anchor_candidates.
        .filter(|anchor| {
            let errors = check_validity_period_at(&anchor.certificate, validation_time);
            if !errors.is_empty() {
                tracing::warn!(
                    "trust anchor '{}' is not valid: {errors:?}",
                    common_name_or_unknown(&anchor.certificate)
                );
            }
            errors.is_empty()
        })
        .any(|anchor| {
            // Check if subject names match.
            let subject_matches =
                anchor.certificate.tbs_certificate.subject == certificate.tbs_certificate.subject;

            if !subject_matches {
                return false;
            }

            // Check if public keys match.
            let pubkey_matches = anchor.certificate.tbs_certificate.subject_public_key_info
                == certificate.tbs_certificate.subject_public_key_info;

            if !pubkey_matches {
                tracing::debug!(
                    "subject names match but public keys differ for: {}",
                    common_name_or_unknown(certificate)
                );
                return false;
            }

            true
        })
}

fn find_trust_anchor_candidates<'a: 'b, 'b>(
    subject: &'a Certificate,
    trust_anchors: &'b TrustAnchorRegistry,
    trust_purpose: TrustPurpose,
    validation_time: OffsetDateTime,
) -> impl Iterator<Item = &'b Certificate> {
    trust_anchors
        .anchors
        .iter()
        .filter_map(move |anchor| {
            if trust_purpose == anchor.purpose {
                Some(&anchor.certificate)
            } else {
                None
            }
        })
        .filter(|candidate| candidate.tbs_certificate.subject == subject.tbs_certificate.issuer)
        .filter(|candidate| {
            let valid = key_identifier_check(
                candidate.tbs_certificate.extensions.iter().flatten(),
                subject.tbs_certificate.extensions.iter().flatten(),
            );
            if !valid {
                tracing::warn!("key identifier extensions did not match");
            }
            valid
        })
        .filter(|candidate| {
            let valid = issuer_signed_subject(subject, candidate);
            if !valid {
                tracing::warn!("issuer did not sign subject");
            }
            valid
        })
        .filter(move |candidate| {
            let errors = check_validity_period_at(candidate, validation_time);
            if !errors.is_empty() {
                tracing::warn!("certificate is not valid: {errors:?}");
            }
            errors.is_empty()
        })
}
