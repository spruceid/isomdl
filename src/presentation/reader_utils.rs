//! Validation of a device response, one document at a time.
//!
//! The entry point is [`validate_response`]. It never returns a single verdict for the
//! response as a whole: a response can carry several independent credentials, so each
//! one is validated separately and reported separately.

use std::collections::{BTreeMap, BTreeSet};

use crate::definitions::{
    device_response::{DeviceResponse, Document},
    helpers::NonEmptyVec,
    session::SessionTranscript,
    x509::{
        self, revocation::RevocationFetcher, trust_anchor::TrustAnchorRegistry,
        validation::ValidationOptions, x5chain::X5CHAIN_COSE_HEADER_LABEL, X5Chain,
    },
    Mso,
};

use super::authentication::{
    mdoc::{check_mso_validity, device_authentication, issuer_authentication},
    DocumentError, DocumentWarning, FailedDocument, RejectedDocument, ResponseError,
    ResponseValidationOutcome, ResponseWarning, ValidatedDocument, VerifiedMso,
};
use super::reader::{parse_response, Error as ReaderError};

use crate::definitions::x509::validation::{CertificateProfile, ProfileSelector};

/// How a reader validates a response.
pub struct ReaderValidationConfig<'a, P: ProfileSelector> {
    /// The roots the issuer's certificate chain must reach. An empty registry is not
    /// "trust everything": every document fails with
    /// [`DocumentError::NoTrustAnchorsConfigured`].
    pub trust_anchors: &'a TrustAnchorRegistry,
    /// The doc types the reader asked for; anything else is rejected unvalidated.
    ///
    /// `None` skips the filter and raises
    /// [`ResponseWarning::RequestedDocTypesUnknown`]. Prefer passing the set: an
    /// unsolicited credential from a trusted issuer is still not an answer.
    pub requested_doc_types: Option<&'a BTreeSet<String>>,
    /// The time certificate and MSO validity windows are checked against.
    pub options: &'a ValidationOptions,
    /// Chooses the certificate profile each document's issuer chain is validated against,
    /// by doc type. A `BTreeMap<String, MdocProfile>` handles a response mixing profiles in
    /// one pass and refuses a doc type it does not cover; [`AnyDocType`] answers with one
    /// profile whatever the doc type.
    ///
    /// [`AnyDocType`]: crate::definitions::x509::validation::AnyDocType
    pub profiles: &'a P,
}

/// Validate every requested document in a device response.
///
/// Documents whose doc type was not requested are **not validated at all** — they are
/// listed in `rejected` and no cryptographic operation is performed on them.
///
/// Pass `&()` as `revocation_fetcher` to skip CRL checks. `e_reader_key_private` is used
/// for ECDH against the device's static key under COSE_Mac0 (ISO/IEC 18013-5 §9.1.3.5) and
/// ignored for COSE_Sign1.
///
/// # Known limitation
///
/// Any trusted root can vouch for any doc type: anchors are scoped by
/// [`TrustPurpose`](crate::definitions::x509::trust_anchor::TrustPurpose), not by doc type.
pub async fn validate_response<S, R, P>(
    device_response: &DeviceResponse,
    session_transcript: &S,
    config: &ReaderValidationConfig<'_, P>,
    revocation_fetcher: &R,
    e_reader_key_private: &[u8; 32],
) -> ResponseValidationOutcome
where
    S: SessionTranscript + Clone,
    R: RevocationFetcher,
    P: ProfileSelector,
{
    let mut warnings = Vec::new();
    if config.requested_doc_types.is_none() {
        warnings.push(ResponseWarning::RequestedDocTypesUnknown);
    }

    let status = Some(device_response.status.clone());
    let document_errors: Vec<_> = device_response
        .document_errors
        .iter()
        .flat_map(|errors| errors.iter().cloned())
        .collect();

    let Some(documents) = device_response.documents.as_ref() else {
        return ResponseValidationOutcome {
            documents: Vec::new(),
            failed: Vec::new(),
            rejected: Vec::new(),
            errors: vec![ResponseError::NoDocuments],
            status,
            document_errors,
            warnings,
        };
    };

    // Partition *before* validating, not after: rejection means no cryptography ran on
    // unsolicited input, which a filter applied to the results would not achieve.
    let mut requested = Vec::new();
    let mut rejected = Vec::new();
    for document in documents.iter() {
        match config.requested_doc_types {
            Some(wanted) if !wanted.contains(&document.doc_type) => {
                rejected.push(RejectedDocument {
                    claimed_doc_type: document.doc_type.clone(),
                });
            }
            _ => requested.push(document),
        }
    }

    let nothing_requested = requested.is_empty();
    let mut validated = Vec::new();
    let mut failed = Vec::new();
    for document in requested {
        // Selection keys on the doc type the holder claims. That can only narrow which
        // certificates are acceptable, and a mislabelled document dies at the
        // `DocTypeMismatch` check against its signature-verified MSO.
        let Some(profile) = config.profiles.issuer_profile_for(&document.doc_type) else {
            failed.push(unprofiled(document));
            continue;
        };
        match validate_document(
            document,
            session_transcript,
            config.trust_anchors,
            revocation_fetcher,
            e_reader_key_private,
            config.options,
            profile,
        )
        .await
        {
            Ok(document) => validated.push(document),
            Err(document) => failed.push(document),
        }
    }

    // The holder answered, but not the question that was asked. That is a failure, not a
    // vacuous success, and it is distinct from every document having been evaluated and
    // rejected on its own merits.
    let mut errors = if nothing_requested {
        vec![ResponseError::AllDocumentsRejected]
    } else {
        Vec::new()
    };
    if !failed.is_empty() {
        errors.push(ResponseError::DocumentsFailed);
    }

    ResponseValidationOutcome {
        documents: validated,
        failed,
        rejected,
        errors,
        status,
        document_errors,
        warnings,
    }
}

/// Validate one document: extract its data *and* decide whether to believe it.
///
/// The order below is the security property. Issuer authentication comes before device
/// authentication because the device key is carried *inside* the MSO — verifying a
/// DeviceAuth signature against a key from an unverified MSO proves only that whoever
/// wrote the response holds the key they themselves put there.
// Both variants are large and equally likely — a document either validates or it doesn't —
// so boxing the error would shrink nothing that matters and cost consumers an indirection.
#[allow(clippy::result_large_err)]
pub async fn validate_document<S, R, P>(
    document: &Document,
    session_transcript: &S,
    trust_anchors: &TrustAnchorRegistry,
    revocation_fetcher: &R,
    e_reader_key_private: &[u8; 32],
    options: &ValidationOptions,
    profile: P,
) -> Result<ValidatedDocument, FailedDocument>
where
    S: SessionTranscript + Clone,
    R: RevocationFetcher,
    P: CertificateProfile,
{
    let mut outcome = Evaluation::new(document);

    // Data is collected whatever the verdict, so a consumer can show a user what was
    // claimed even when the document fails.
    decode_namespaces(document, &mut outcome);

    let x5chain = match extract_x5chain(document) {
        Ok(x5chain) => x5chain,
        Err(e) => {
            outcome.errors.push(e);
            outcome
                .errors
                .push(DocumentError::DeviceAuthenticationNotAttempted {
                    detail: "the issuer's certificate chain is unusable".to_string(),
                });
            return outcome.finish();
        }
    };

    // An empty registry is a deployment error, and is worth telling apart from a
    // populated registry that simply has no anchor for this chain — that case falls
    // through to `CertificateChain` below. Today both look identical to an operator.
    if trust_anchors.anchors.is_empty() {
        outcome.errors.push(DocumentError::NoTrustAnchorsConfigured);
        outcome
            .errors
            .push(DocumentError::DeviceAuthenticationNotAttempted {
                detail: "there is no trust anchor to authenticate the issuer against".to_string(),
            });
        return outcome.finish();
    }

    let validation = x509::validation::validate_with_options(
        &profile,
        &x5chain,
        trust_anchors,
        revocation_fetcher,
        options,
    )
    .await;

    // Revocation *failures* are infrastructure problems, not evidence of revocation —
    // an actually revoked certificate shows up in `validation.errors`.
    outcome.warnings.extend(
        validation
            .revocation_errors
            .into_iter()
            .map(|detail| DocumentWarning::Revocation { detail }),
    );

    if !validation.errors.is_empty() {
        outcome.errors.extend(
            validation
                .errors
                .into_iter()
                .map(|detail| DocumentError::CertificateChain { detail }),
        );
        outcome
            .errors
            .push(DocumentError::DeviceAuthenticationNotAttempted {
                detail: "the issuer's certificate chain did not validate".to_string(),
            });
        return outcome.finish();
    }

    let mso = match issuer_authentication(x5chain, &document.issuer_signed) {
        Ok(mso) => mso,
        Err(e) => {
            outcome.errors.push(issuer_error(e));
            outcome
                .errors
                .push(DocumentError::DeviceAuthenticationNotAttempted {
                    detail: "issuer authentication did not succeed".to_string(),
                });
            return outcome.finish();
        }
    };

    outcome.mso = Some(VerifiedMso::from_verified(&mso));

    // The holder writes `document.doc_type`; the issuer signs `mso.doc_type`. They are
    // allowed to disagree on the wire, and nothing in this crate used to notice.
    if mso.doc_type != document.doc_type {
        outcome.errors.push(DocumentError::DocTypeMismatch {
            claimed: document.doc_type.clone(),
            authenticated: mso.doc_type.clone(),
        });
    }

    // Only now is the validity window worth reading: it is part of what the issuer
    // signed.
    match check_mso_validity(&mso.validity_info, options.validation_time()) {
        Ok(()) => {}
        Err(ReaderError::MsoExpired) => outcome.errors.push(DocumentError::MsoExpired),
        Err(ReaderError::MsoNotYetValid) => outcome.errors.push(DocumentError::MsoNotYetValid),
        Err(e) => outcome.errors.push(DocumentError::Other {
            code: "mso_validity".to_string(),
            detail: e.to_string(),
        }),
    }

    device_auth(
        document,
        &mso,
        session_transcript,
        e_reader_key_private,
        &mut outcome,
    );

    outcome.finish()
}

/// A document whose doc type no configured profile covers.
///
/// Refused before any cryptography: with no profile there is no rule to validate the
/// chain against, and guessing one would accept or reject the wrong certificates.
fn unprofiled(document: &Document) -> FailedDocument {
    let mut evaluation = Evaluation::new(document);
    decode_namespaces(document, &mut evaluation);
    FailedDocument {
        claimed_doc_type: document.doc_type.clone(),
        errors: NonEmptyVec::new(DocumentError::NoProfileConfigured {
            doc_type: document.doc_type.clone(),
        }),
        // Refused before any cryptography ran, so there is nothing verified to report.
        mso: None,
        namespaces: evaluation.namespaces,
        warnings: evaluation.warnings,
    }
}

/// A document being evaluated, before it is known which of the two outcomes it is.
struct Evaluation {
    claimed_doc_type: String,
    mso: Option<VerifiedMso>,
    namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    errors: Vec<DocumentError>,
    warnings: Vec<DocumentWarning>,
}

impl Evaluation {
    fn new(document: &Document) -> Self {
        Self {
            claimed_doc_type: document.doc_type.clone(),
            mso: None,
            namespaces: BTreeMap::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[allow(clippy::result_large_err)]
    fn finish(self) -> Result<ValidatedDocument, FailedDocument> {
        let failed = |errors| {
            Err(FailedDocument {
                claimed_doc_type: self.claimed_doc_type.clone(),
                errors,
                mso: self.mso.clone(),
                namespaces: self.namespaces.clone(),
                warnings: self.warnings.clone(),
            })
        };

        if let Ok(errors) = NonEmptyVec::try_from(self.errors.clone()) {
            return failed(errors);
        }

        // No errors but no MSO would mean a path returned without recording why. Not
        // reachable today; reported rather than panicked so it stays that way.
        let Some(mso) = self.mso.clone() else {
            return failed(NonEmptyVec::new(DocumentError::Other {
                code: "not_evaluated".to_string(),
                detail: "validation finished without authenticating the issuer".to_string(),
            }));
        };

        Ok(ValidatedDocument {
            doc_type: mso.doc_type.clone(),
            namespaces: self.namespaces,
            mso,
            warnings: self.warnings,
        })
    }
}

fn device_auth<S>(
    document: &Document,
    mso: &Mso,
    session_transcript: &S,
    e_reader_key_private: &[u8; 32],
    outcome: &mut Evaluation,
) where
    S: SessionTranscript + Clone,
{
    if let Err(e) = device_authentication(
        document,
        mso,
        session_transcript.clone(),
        e_reader_key_private,
    ) {
        outcome.errors.push(DocumentError::DeviceAuthentication {
            detail: e.to_string(),
        });
    }
}

/// Decode every disclosed element of every namespace into JSON.
///
/// An element that cannot be represented is reported by identifier and left out; its
/// siblings are still returned, and the document can still validate. Its digest was
/// already verified, so this is a limitation of the JSON projection, not evidence against
/// the credential — but dropping it silently would make a partial disclosure
/// indistinguishable from a complete one.
fn decode_namespaces(document: &Document, outcome: &mut Evaluation) {
    let Some(namespaces) = document.issuer_signed.namespaces.as_ref() else {
        outcome.errors.push(DocumentError::NoNamespaces);
        return;
    };

    for (namespace, items) in namespaces.iter() {
        let decoded = outcome.namespaces.entry(namespace.clone()).or_default();
        for item in items.iter() {
            let item = item.as_ref();
            match parse_response(item.element_value.clone()) {
                Ok(value) => {
                    decoded.insert(item.element_identifier.clone(), value);
                }
                Err(e) => outcome.warnings.push(DocumentWarning::UndecodableElement {
                    namespace: namespace.clone(),
                    element_identifier: item.element_identifier.clone(),
                    detail: e.to_string(),
                }),
            }
        }
    }
}

fn extract_x5chain(document: &Document) -> Result<X5Chain, DocumentError> {
    document
        .issuer_signed
        .issuer_auth
        .unprotected
        .rest
        .iter()
        .find(|(label, _)| label == &coset::Label::Int(X5CHAIN_COSE_HEADER_LABEL))
        .map(|(_, value)| value.to_owned())
        .ok_or(DocumentError::MissingX5Chain)
        .and_then(|value| {
            X5Chain::from_cbor(value).map_err(|e| DocumentError::MalformedX5Chain {
                detail: e.to_string(),
            })
        })
}

/// Distinguish "the MSO could not be read" from "the MSO was not authentic".
fn issuer_error(e: ReaderError) -> DocumentError {
    match e {
        ReaderError::MSOParsing | ReaderError::DetachedIssuerAuth => DocumentError::MalformedMso {
            detail: e.to_string(),
        },
        e => DocumentError::IssuerAuthentication {
            detail: e.to_string(),
        },
    }
}

#[cfg(test)]
#[path = "tests/reader_utils.rs"]
mod test;
