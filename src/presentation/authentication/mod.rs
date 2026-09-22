use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::definitions::device_request::ItemsRequest;
use crate::definitions::device_response::{DocumentErrorCode, Status};
use crate::definitions::{helpers::NonEmptyVec, mso::DigestAlgorithm, Mso};
use crate::presentation::device::RequestedItems;

/// Module containing functions to perform mdoc authentication.
pub mod mdoc;

/// The outcome of the holder device processing a device request.
///
/// Reader authentication is optional in ISO/IEC 18013-5, so whether an *absent* `readerAuth`
/// is acceptable is the holder's policy, stated by registering reader trust anchors: with
/// anchors configured its absence is an error, without them a warning.
///
/// A `readerAuth` that is *present* is always verified and always an error when it does not
/// hold up — a holder with no anchors still checks the signature rather than waving the
/// request through. Empty `errors` therefore means "authenticated, or not required here".
///
/// [`DocRequestAuthenticationOutcome::is_reader_authenticated`] answers the narrower
/// question, and gates [`DocRequestAuthenticationOutcome::common_name`] — that name is
/// read out of the certificate before its signature is verified.
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq)]
pub struct RequestAuthenticationOutcome {
    /// One entry per `DocRequest`, in the order the reader sent them.
    ///
    /// Each carries its own reader-authentication result: `reader_auth` is a field of
    /// `DocRequest`, not of `DeviceRequest`, so two doc requests can be signed by
    /// certificates with different common names. An aggregate would attribute every
    /// requested element to whichever reader happened to come first.
    pub doc_requests: Vec<DocRequestAuthenticationOutcome>,
    /// Errors concerning the request as a whole, not any one doc request.
    pub errors: Errors,
    /// Non-fatal warnings concerning the request as a whole.
    pub warnings: Errors,
}

impl RequestAuthenticationOutcome {
    /// Whether anything went wrong, at either level.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty() || self.doc_requests.iter().any(|d| !d.errors.is_empty())
    }

    /// Everything the reader asked for, authenticated or not.
    ///
    /// This is what `prepare_response` wants. Prefer
    /// [`Self::authenticated_requested_items`] unless you deliberately intend to serve
    /// unauthenticated readers.
    pub fn requested_items(&self) -> RequestedItems {
        self.doc_requests
            .iter()
            .map(|d| d.items_request.clone())
            .collect()
    }

    /// Only what an authenticated reader asked for.
    pub fn authenticated_requested_items(&self) -> RequestedItems {
        self.doc_requests
            .iter()
            .filter(|d| d.is_reader_authenticated())
            .map(|d| d.items_request.clone())
            .collect()
    }
}

/// The outcome for a single `DocRequest`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DocRequestAuthenticationOutcome {
    /// What this doc request asks for.
    pub items_request: ItemsRequest,
    /// Whether the reader supplied a `readerAuth` signature at all.
    ///
    /// Distinguishes "unauthenticated" from "failed authentication". Whether its absence
    /// is an error or a warning depends on the holder's trust anchors — see
    /// [`RequestAuthenticationOutcome`].
    pub reader_auth_present: bool,
    /// The common name from the certificate that signed this doc request.
    ///
    /// Read before the signature is verified, so it identifies the reader only when
    /// [`Self::is_reader_authenticated`] holds. Displaying it otherwise tells the user
    /// who the request *claims* to be from.
    pub common_name: Option<String>,
    /// Errors that occurred while processing this doc request.
    pub errors: Errors,
    /// Non-fatal warnings, such as CRL fetch failures.
    pub warnings: Errors,
}

impl DocRequestAuthenticationOutcome {
    /// Whether this doc request carried a reader signature that verified against a
    /// trusted chain.
    pub fn is_reader_authenticated(&self) -> bool {
        self.reader_auth_present && self.errors.is_empty()
    }
}

/// Errors that occur during request processing.
pub type Errors = BTreeMap<String, serde_json::Value>;

/// The outcome of a reader validating a device response.
///
/// A response may carry several credentials, each cryptographically independent, so every
/// document is validated and reported on its own.
///
/// These types round-trip through JSON so consumers can persist an outcome, which means a
/// [`ValidatedDocument`] can be deserialized from anything. A deserialized outcome is a
/// record of a past validation, not evidence of one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseValidationOutcome {
    /// Documents that passed every check, in wire order. Two may share a doc type —
    /// ISO/IEC 18013-5:2021 does not forbid duplicates.
    pub documents: Vec<ValidatedDocument>,
    /// Documents that were evaluated and did not pass.
    pub failed: Vec<FailedDocument>,
    /// Documents the reader did not ask for. **Not validated at all.**
    pub rejected: Vec<RejectedDocument>,
    /// Every reason this response is not wholly good, including
    /// [`DocumentsFailed`](ResponseError::DocumentsFailed) whenever
    /// [`failed`](Self::failed) is non-empty.
    ///
    /// Empty means every document that *arrived* validated. It does not mean everything
    /// asked for arrived: a subset response is legal, so a reader that needs a particular
    /// credential must look for it in [`documents`](Self::documents) rather than infer it
    /// from this being empty.
    pub errors: Vec<ResponseError>,
    /// The holder's own status code, carried verbatim and never turned into an error.
    ///
    /// `None` when the response could not be decoded far enough to have one. A response
    /// whose documents all validate is good regardless of this field, which the holder
    /// also controls.
    pub status: Option<Status>,
    /// What the holder said it could not return, keyed by doc type.
    ///
    /// Informational, not a failure: a subset response is legal, and this is the holder
    /// saying *why* a doc type is absent rather than leaving the reader to guess. Its
    /// absence means nothing — the channel is optional.
    pub document_errors: Vec<BTreeMap<String, DocumentErrorCode>>,
    pub warnings: Vec<ResponseWarning>,
}

/// A document whose issuer signature, certificate chain, digests, and device signature all
/// verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedDocument {
    /// Taken from the signature-verified MSO, not the holder's label.
    pub doc_type: String,
    /// The disclosed elements, by namespace then element identifier.
    pub namespaces: BTreeMap<String, BTreeMap<String, Value>>,
    /// What the issuer committed to. Use it for policy the library cannot decide: how
    /// close to `valid_until` is too close, whether the digest algorithm meets your bar.
    pub mso: VerifiedMso,
    /// Issues that did not prevent the document from validating.
    pub warnings: Vec<DocumentWarning>,
}

/// A document that was evaluated and did not pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FailedDocument {
    /// The doc type as the holder labelled it. Unauthenticated — display it to explain
    /// the failure, never decide on it.
    pub claimed_doc_type: String,
    pub errors: NonEmptyVec<DocumentError>,
    /// The issuer's signed statement, present only when issuer authentication succeeded
    /// and the document failed later — an expired MSO, a doc type disagreeing with
    /// [`claimed_doc_type`](Self::claimed_doc_type), or device authentication.
    ///
    /// Its presence is not a verdict: this document failed. It is here so a consumer can
    /// say *why* — the expiry date, the issuer-signed doc type — without re-parsing the
    /// response.
    pub mso: Option<VerifiedMso>,
    /// The elements as disclosed, for showing a user what was *claimed*. Unverified.
    pub namespaces: BTreeMap<String, BTreeMap<String, Value>>,
    /// Issues that are not themselves the reason for failure.
    pub warnings: Vec<DocumentWarning>,
}

/// A document that was not evaluated because the reader never asked for its doc type.
///
/// No cryptographic operation is performed on an unrequested document: refusing to
/// process unsolicited input is cheaper and safer than processing it and discarding
/// the result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectedDocument {
    /// The doc type the holder claimed. Unauthenticated by definition.
    pub claimed_doc_type: String,
}

/// Facts read out of an MSO whose COSE_Sign1 signature was verified against a chain
/// rooted in a configured trust anchor.
///
/// The validity window is copied out of [`ValidityInfo`](crate::definitions::ValidityInfo)
/// rather than embedded, because its `Serialize` emits the CBOR wire encoding (tagged
/// `tdate` values),
/// which JSON cannot represent — and these outcome types are meant to be persisted and
/// shipped as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedMso {
    /// The doc type the *issuer* signed. Authoritative.
    pub doc_type: String,
    /// The MSO version.
    pub version: String,
    /// The digest algorithm the issuer committed with.
    pub digest_algorithm: DigestAlgorithm,
    /// When the issuer signed the credential.
    #[serde(with = "time::serde::rfc3339")]
    pub signed: OffsetDateTime,
    /// Start of the credential's validity window.
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: OffsetDateTime,
    /// End of the credential's validity window.
    #[serde(with = "time::serde::rfc3339")]
    pub valid_until: OffsetDateTime,
    /// When the issuer expects to publish an update. Not a window bound.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub expected_update: Option<OffsetDateTime>,
}

impl VerifiedMso {
    /// Copy the authenticated facts out of a signature-verified MSO.
    pub(crate) fn from_verified(mso: &Mso) -> Self {
        Self {
            doc_type: mso.doc_type.clone(),
            version: mso.version.clone(),
            digest_algorithm: mso.digest_algorithm,
            signed: mso.validity_info.signed,
            valid_from: mso.validity_info.valid_from,
            valid_until: mso.validity_info.valid_until,
            expected_update: mso.validity_info.expected_update,
        }
    }
}

/// Something that went wrong while validating a single document.
///
/// Consumers must treat [`DocumentError::Other`] as "unknown failure, do not accept":
/// it is where new failure modes appear in minor releases, and it is promoted to a
/// named variant at the next major.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DocumentError {
    #[error("the document carries no x5chain, so its issuer cannot be identified")]
    MissingX5Chain,
    #[error("the document's x5chain could not be decoded: {detail}")]
    MalformedX5Chain { detail: String },
    /// No trust anchors are configured at all — a deployment error, not a bad credential.
    ///
    /// Distinct from [`DocumentError::CertificateChain`], which is what a *populated*
    /// registry containing no anchor for this chain produces.
    #[error("no trust anchors are configured, so no issuer can be authenticated")]
    NoTrustAnchorsConfigured,
    /// No certificate profile covers this doc type, so there is no rule to validate its
    /// chain against. Refused rather than validated under a guess.
    #[error("no certificate profile is configured for doc type {doc_type}")]
    NoProfileConfigured { doc_type: String },
    #[error("certificate chain validation failed: {detail}")]
    CertificateChain { detail: String },
    #[error("issuer authentication failed: {detail}")]
    IssuerAuthentication { detail: String },
    #[error("the MSO could not be decoded: {detail}")]
    MalformedMso { detail: String },
    /// The holder labelled the document with a doc type the issuer did not sign.
    #[error("document claims doc type {claimed}, but its MSO says {authenticated}")]
    DocTypeMismatch {
        claimed: String,
        authenticated: String,
    },
    #[error("the credential has expired")]
    MsoExpired,
    #[error("the credential is not yet valid")]
    MsoNotYetValid,
    #[error("device authentication failed: {detail}")]
    DeviceAuthentication { detail: String },
    /// Device authentication could not be performed, because the device key lives in
    /// an MSO that was never authenticated.
    ///
    /// Always accompanied by the error that made the MSO untrustworthy; a consumer
    /// rendering failures should not surface this one separately.
    #[error("device authentication was not attempted: {detail}")]
    DeviceAuthenticationNotAttempted { detail: String },
    #[error("the document discloses no namespaces")]
    NoNamespaces,
    #[error("{code}: {detail}")]
    Other { code: String, detail: String },
}

impl DocumentError {
    /// A stable discriminant, for consumers that branch without parsing the message.
    pub fn code(&self) -> &str {
        match self {
            Self::MissingX5Chain => "missing_x5chain",
            Self::MalformedX5Chain { .. } => "malformed_x5chain",
            Self::NoTrustAnchorsConfigured => "no_trust_anchors_configured",
            Self::NoProfileConfigured { .. } => "no_profile_configured",
            Self::CertificateChain { .. } => "certificate_chain",
            Self::IssuerAuthentication { .. } => "issuer_authentication",
            Self::MalformedMso { .. } => "malformed_mso",
            Self::DocTypeMismatch { .. } => "doc_type_mismatch",
            Self::MsoExpired => "mso_expired",
            Self::MsoNotYetValid => "mso_not_yet_valid",
            Self::DeviceAuthentication { .. } => "device_authentication",
            Self::DeviceAuthenticationNotAttempted { .. } => "device_authentication_not_attempted",
            Self::NoNamespaces => "no_namespaces",
            Self::Other { code, .. } => code,
        }
    }
}

/// A non-fatal issue with a single document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DocumentWarning {
    /// The revocation status could not be established. The certificate was *not* found
    /// to be revoked — that is a [`DocumentError::CertificateChain`].
    #[error("revocation status could not be determined: {detail}")]
    Revocation { detail: String },
    /// A disclosed element could not be represented as JSON, so it is absent from
    /// [`ValidatedDocument::namespaces`]. Not a failure — the issuer signed it and its
    /// digest matched, this library just cannot render it. Named rather than dropped, so a
    /// partial disclosure stays distinguishable from a complete one.
    #[error(
        "element {element_identifier} in namespace {namespace} could not be decoded: {detail}"
    )]
    UndecodableElement {
        namespace: String,
        element_identifier: String,
        detail: String,
    },
    #[error("{code}: {detail}")]
    Other { code: String, detail: String },
}

impl DocumentWarning {
    /// A stable discriminant, for consumers that branch without parsing the message.
    pub fn code(&self) -> &str {
        match self {
            Self::Revocation { .. } => "revocation",
            Self::UndecodableElement { .. } => "undecodable_element",
            Self::Other { code, .. } => code,
        }
    }
}

/// Why a response could not be evaluated at all.
///
/// The variants are mutually exclusive by construction and checked in the order they
/// are declared, so no precedence rule is needed.
///
/// As with [`DocumentError::Other`], treat [`ResponseError::Other`] as "unknown
/// failure, do not accept".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponseError {
    #[error("the response could not be decrypted: {detail}")]
    Decryption { detail: String },
    #[error("the response could not be decoded: {detail}")]
    CborDecoding { detail: String },
    /// The `documents` field was absent. Check
    /// [`status`](ResponseValidationOutcome::status) and
    /// [`document_errors`](ResponseValidationOutcome::document_errors) for what the holder
    /// said about it.
    #[error("the response contains no documents")]
    NoDocuments,
    /// At least one requested document was evaluated and did not pass. The reasons are on
    /// the document itself, in [`failed`](ResponseValidationOutcome::failed).
    ///
    /// Present so that `errors.is_empty()` is a complete verdict: without it a response
    /// whose only document failed device authentication would report no errors at all.
    #[error("at least one document failed validation")]
    DocumentsFailed,
    /// Documents were present, but none of a doc type the reader asked for.
    #[error("the response contains no document of a requested doc type")]
    AllDocumentsRejected,
    #[error("{code}: {detail}")]
    Other { code: String, detail: String },
}

impl ResponseError {
    /// A stable discriminant, for consumers that branch without parsing the message.
    pub fn code(&self) -> &str {
        match self {
            Self::Decryption { .. } => "decryption",
            Self::CborDecoding { .. } => "cbor_decoding",
            Self::NoDocuments => "no_documents",
            Self::DocumentsFailed => "documents_failed",
            Self::AllDocumentsRejected => "all_documents_rejected",
            Self::Other { code, .. } => code,
        }
    }
}

/// A non-fatal issue with the response as a whole.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponseWarning {
    /// The caller did not say which doc types it requested, so unsolicited documents
    /// could not be filtered out and were validated like any other.
    #[error("the requested doc types are unknown, so unsolicited documents were not rejected")]
    RequestedDocTypesUnknown,
    #[error("{code}: {detail}")]
    Other { code: String, detail: String },
}

impl ResponseWarning {
    /// A stable discriminant, for consumers that branch without parsing the message.
    pub fn code(&self) -> &str {
        match self {
            Self::RequestedDocTypesUnknown => "requested_doc_types_unknown",
            Self::Other { code, .. } => code,
        }
    }
}

impl ResponseValidationOutcome {
    /// The single validated document, if there is exactly one.
    ///
    /// `None` both when nothing validated and when several did — a reader expecting one
    /// credential should not silently pick from several.
    pub fn single_document(&self) -> Option<&ValidatedDocument> {
        match self.documents.as_slice() {
            [document] => Some(document),
            _ => None,
        }
    }

    /// The validated document with this doc type, if there is exactly one.
    pub fn document(&self, doc_type: &str) -> Option<&ValidatedDocument> {
        let mut matching = self.documents.iter().filter(|d| d.doc_type == doc_type);
        match (matching.next(), matching.next()) {
            (Some(document), None) => Some(document),
            _ => None,
        }
    }
}
