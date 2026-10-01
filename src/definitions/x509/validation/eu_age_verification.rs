//! The EU age verification certificate profile.
//!
//! `eu.europa.ec.av.1` is an mdoc, but its PKI is not ISO/IEC 18013-5 Annex B's. It defines
//! no mdoc key-purpose OIDs at all, so no [`MdocProfile`](super::MdocProfile) constant can
//! express it — which is what [`CertificateProfile`] exists for.

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::Decode;
use x509_cert::{ext::pkix::CertificatePolicies, Certificate};

use super::{CertificateProfile, ChainRule, RevocationRule};
use crate::definitions::x509::trust_anchor::TrustPurpose;

/// The doc type these rules apply to.
pub const EU_AGE_VERIFICATION_DOC_TYPE: &str = "eu.europa.ec.av.1";

/// ETSI EN 319 411-1 normalised certificate policy (NCP).
pub const NCP_POLICY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.2042.1.1");

/// The document signer profile for EU age verification credentials.
///
/// Three things differ from ISO/IEC 18013-5 Annex B, and none of them is an OID value:
///
/// - **No mdoc key purpose.** The architecture asks for a document signer "compliant with
///   ETSI EN 319 411-1 NCP policy", so what identifies a conformant signer is the
///   [`NCP_POLICY_OID`] certificate policy rather than an `extendedKeyUsage`.
/// - **Trusted List, not IACA.** Trust comes from membership of an EC-managed
///   ETSI TS 119 612 Trusted List. Supply those certificates as
///   [`TrustPurpose::Iaca`] anchors; this profile places no requirement on their shape,
///   and none on names shared with the signer — Annex B's matching `countryName` rule does
///   not apply.
/// - **Intermediate CAs.** ETSI PKIs use them, and Annex B forbids them, so the chain is
///   walked rather than taken one certificate deep.
///
/// # What this does not check
///
/// Only the policy assertion, the chain, and validity periods. It does not attempt to
/// re-derive EN 319 411-1 conformance from the certificate: that is the Trusted List
/// operator's judgement, and inventing extra requirements here would reject conformant
/// credentials. Revocation is out of band too, so a signer carrying no
/// `cRLDistributionPoints` produces a revocation *warning* rather than an error — "not
/// checked" stays visible rather than being silently dropped.
///
/// # Reader certificates
///
/// This is the issuer half only. The scheme's rules for relying-party certificates are not
/// modelled here, so pair it with whatever your deployment requires:
///
/// ```
/// use isomdl::definitions::x509::validation::{EuAgeVerificationProfile, MdocProfile};
///
/// let profile = MdocProfile {
///     issuer: EuAgeVerificationProfile,
///     reader: MdocProfile::MDL.reader,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EuAgeVerificationProfile;

impl CertificateProfile for EuAgeVerificationProfile {
    fn validate_end_entity(&self, certificate: &Certificate) -> Vec<String> {
        let Some(extension) = certificate
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|extension| extension.extn_id == CertificatePolicies::OID)
        else {
            return vec!["certificatepolicies: required extension not found".to_string()];
        };

        let policies = match CertificatePolicies::from_der(extension.extn_value.as_bytes()) {
            Ok(policies) => policies,
            Err(e) => return vec![format!("certificatepolicies: cannot be decoded: {e}")],
        };

        if policies
            .0
            .iter()
            .any(|policy| policy.policy_identifier == NCP_POLICY_OID)
        {
            Vec::new()
        } else {
            vec![format!(
                "certificatepolicies: does not assert the ETSI NCP policy {NCP_POLICY_OID}"
            )]
        }
    }

    fn trust_purpose(&self) -> TrustPurpose {
        TrustPurpose::Iaca
    }

    /// Trust comes from Trusted List membership, not from the anchor's shape.
    fn validate_trust_anchor(&self, _certificate: &Certificate) -> Vec<String> {
        Vec::new()
    }

    /// ETSI constrains no name shared between a signer and its CA, unlike Annex B's
    /// matching `countryName`.
    fn validate_against_trust_anchor(
        &self,
        _signer: &Certificate,
        _trust_anchor: &Certificate,
    ) -> Vec<String> {
        Vec::new()
    }

    /// ETSI PKIs use intermediate CAs, which Annex B forbids.
    fn chain(&self) -> ChainRule {
        ChainRule::WalkToTrustAnchor
    }

    /// Revocation is the Trusted List's business, not a CRL named by the certificate.
    fn revocation(&self) -> RevocationRule {
        RevocationRule::OutOfBand
    }

    fn end_entity_name(&self) -> &'static str {
        "AV document signer certificate"
    }

    fn trust_anchor_name(&self) -> &'static str {
        "AV Trusted List certificate"
    }
}
