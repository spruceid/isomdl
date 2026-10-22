//! Reader-side verification of the MSO status list (ISO/IEC 18013-5 second edition CD
//! 12.3.6, draft-ietf-oauth-status-list-10).
//!
//! <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html>

use crate::{
    cbor,
    cose::MaybeTagged,
    definitions::x509::{
        revocation::RevocationFetcher,
        trust_anchor::{TrustAnchor, TrustAnchorRegistry},
        validation::{
            validate_with_options, CertificateProfile, StatusListSignerProfile, ValidationOptions,
        },
        x5chain::X5CHAIN_COSE_HEADER_LABEL,
        SupportedCurve, X5Chain,
    },
    definitions::StatusListInfo,
};
use ciborium::{value::Integer, Value};
use coset::{CoseSign1, Label, RegisteredLabelWithPrivate};
use flate2::bufread::ZlibDecoder;
use std::io::Read;
use time::OffsetDateTime;
use x509_cert::{der::Decode, Certificate};

mod fetcher;

#[cfg(feature = "reqwest")]
pub use fetcher::CachingStatusListFetcher;
pub use fetcher::{SimpleStatusListFetcher, StatusListFetcher};

/// The `typ` of a Status List Token in CWT form. The CoAP Content-Format ID that draft-10
/// 5.2 also allows is still "TBD" (14.8), so there is no number to accept.
pub const STATUS_LIST_CWT_TYPE: &str = "application/statuslist+cwt";

/// A decoded Status List Token. Nothing in it is verified yet: the caller checks the
/// signature, `x5chain`, `sub` and `exp`.
#[derive(Debug, Clone)]
pub struct StatusListToken {
    /// Kept for the signature check, and for `x5chain` in the protected header (33).
    pub cose_sign1: MaybeTagged<CoseSign1>,
    /// Claim 2. Must equal the `uri` of the MSO `status_list`.
    pub sub: String,
    /// Claim 6.
    pub iat: OffsetDateTime,
    /// Claim 4. Optional in draft-10, required by ISO/IEC 18013-5 12.3.6.3.
    pub exp: OffsetDateTime,
    /// Claim 65534, in seconds.
    pub ttl: Option<u64>,
    /// `bits` of claim 65533. Not checked here: [`status_at`] refuses an invalid size.
    pub bits: u8,
    /// `lst` of claim 65533, zlib-compressed. Read it with [`compressed_status_at`].
    pub lst: Vec<u8>,
}

/// Decode a Status List Token in CWT form:
/// <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html#name-status-list-token-in-cwt-format>.
pub fn decode_token(bytes: &[u8]) -> Result<StatusListToken, StatusListError> {
    // Tagged (18) or untagged: the draft examples changed between the two.
    let cose_sign1 = cbor::from_slice::<MaybeTagged<CoseSign1>>(bytes)
        .map_err(|e| StatusListError::MalformedToken(e.to_string()))?;

    // coset 0.3.8 has no `typ` field, so the label lands in `rest`.
    let typ = protected_header(&cose_sign1, TYP_HEADER_LABEL);
    if typ.and_then(Value::as_text) != Some(STATUS_LIST_CWT_TYPE) {
        return Err(StatusListError::WrongType);
    }

    let payload = cose_sign1
        .payload
        .as_deref()
        .ok_or_else(|| StatusListError::MalformedToken("the payload is detached".into()))?;

    // Not `coset::cwt::ClaimsSet`: coset 0.3.8 refuses the claim keys 65533 and 65534, which
    // are neither in its IANA table nor in the private-use range.
    let mut claims = cbor::from_slice::<Value>(payload)
        .map_err(|e| StatusListError::MalformedToken(e.to_string()))?
        .into_map()
        .map_err(|_| StatusListError::MalformedToken("the payload is not a map".into()))?;

    let sub = required(&mut claims, 2.into(), "sub")?
        .into_text()
        .map_err(|_| StatusListError::MalformedClaim("sub"))?;
    let iat = timestamp(required(&mut claims, 6.into(), "iat")?, "iat")?;
    let exp = timestamp(required(&mut claims, 4.into(), "exp")?, "exp")?;
    let ttl = take(&mut claims, 65534.into())
        .map(|ttl| integer(ttl, "ttl"))
        .transpose()?;

    let mut status_list = required(&mut claims, 65533.into(), "status_list")?
        .into_map()
        .map_err(|_| StatusListError::MalformedClaim("status_list"))?;
    let bits = integer(required(&mut status_list, "bits".into(), "bits")?, "bits")?;
    let lst = required(&mut status_list, "lst".into(), "lst")?
        .into_bytes()
        .map_err(|_| StatusListError::MalformedClaim("lst"))?;

    Ok(StatusListToken {
        cose_sign1,
        sub,
        iat,
        exp,
        ttl,
        bits,
        lst,
    })
}

/// Fetch, verify and read the status of the MSO that carries `status_list`.
///
/// `iaca` is the trust anchor of the document signer chain. It is the trust point when
/// `status_list` has no `certificate` (ISO/IEC 18013-5 second edition CD 12.3.6.2).
///
/// On success, returns the status and the CRL failures of the signer chain (see
/// [`verify_token`]).
pub async fn check_status<R: RevocationFetcher, F: StatusListFetcher>(
    status_list: &StatusListInfo,
    iaca: &Certificate,
    revocation_fetcher: &R,
    status_list_fetcher: &F,
    options: &ValidationOptions,
) -> Result<(u8, Vec<String>), StatusListError> {
    // Authentic: the MSO that carries it is signature-verified.
    let certificate;
    let trust_point = match &status_list.certificate {
        Some(der) => {
            certificate = Certificate::from_der(der.as_ref())
                .map_err(|e| StatusListError::MalformedCertificate(e.to_string()))?;
            &certificate
        }
        None => iaca,
    };

    let bytes = status_list_fetcher
        .fetch_status_list_token(&status_list.uri)
        .await?;
    let token = decode_token(&bytes)?;
    let warnings = verify_token(
        &token,
        &status_list.uri,
        trust_point,
        revocation_fetcher,
        options,
    )
    .await?;
    let status = compressed_status_at(&token.lst, token.bits, status_list.idx)?;
    Ok((status, warnings))
}

/// Verify a decoded token for the MSO `status_list` that references it by `uri`.
///
/// `trust_point` is the certificate of ISO/IEC 18013-5 second edition CD 12.3.6.2: the
/// `certificate` of the MSO status, or else the IACA that signed the document signer. The
/// top certificate of the token `x5chain` must be the trust point or be signed by it.
///
/// On success, returns the CRL failures of the signer chain. Like for the document signer,
/// a CRL that cannot be read does not invalidate the token: the caller reports them as
/// warnings. A revoked signer certificate is an error.
pub async fn verify_token<R: RevocationFetcher>(
    token: &StatusListToken,
    uri: &str,
    trust_point: &Certificate,
    revocation_fetcher: &R,
    options: &ValidationOptions,
) -> Result<Vec<String>, StatusListError> {
    // 12.3.6.3: in the protected header. The MSO has its `x5chain` in the unprotected one.
    let x5chain = protected_header(&token.cose_sign1, X5CHAIN_COSE_HEADER_LABEL)
        .ok_or(StatusListError::MissingX5Chain)?;
    let x5chain = X5Chain::from_cbor(x5chain.clone())
        .map_err(|e| StatusListError::MalformedX5Chain(e.to_string()))?;

    // Local and cheap, so before the chain validation, which can fetch CRLs.
    verify_signature(&token.cose_sign1, &x5chain)?;

    let trust_point = TrustAnchorRegistry {
        anchors: vec![TrustAnchor {
            certificate: trust_point.clone(),
            purpose: StatusListSignerProfile.trust_purpose(),
        }],
    };
    let validation = validate_with_options(
        &StatusListSignerProfile,
        &x5chain,
        &trust_point,
        revocation_fetcher,
        options,
    )
    .await;
    if !validation.errors.is_empty() {
        return Err(StatusListError::UntrustedSigner(validation.errors));
    }

    if token.sub != uri {
        return Err(StatusListError::SubjectMismatch {
            expected: uri.to_string(),
            found: token.sub.clone(),
        });
    }
    if token.exp <= options.validation_time() {
        return Err(StatusListError::Expired(token.exp));
    }

    Ok(validation.revocation_errors)
}

/// ES256 with a P-256 key and ES384 with a P-384 key, as for the MSO. 12.3.6.3 also allows
/// ES512, EdDSA and brainpool curves, which fail here.
fn verify_signature(
    cose_sign1: &MaybeTagged<CoseSign1>,
    x5chain: &X5Chain,
) -> Result<(), StatusListError> {
    // `MaybeTagged::verify` compares `alg` with the key only when `alg` is a registered
    // value. Without this check, a token with no `alg` would pass.
    if !matches!(
        cose_sign1.protected.header.alg,
        Some(RegisteredLabelWithPrivate::Assigned(_))
    ) {
        return Err(StatusListError::Signature(
            "the protected header has no registered alg".into(),
        ));
    }

    let key_error = |e: anyhow::Error| StatusListError::Signature(e.to_string());
    let result = match SupportedCurve::from_certificate(x5chain.end_entity_certificate()) {
        Some(SupportedCurve::P256) => {
            let key: p256::ecdsa::VerifyingKey =
                x5chain.end_entity_public_key().map_err(key_error)?;
            cose_sign1.verify::<_, p256::ecdsa::Signature>(&key, None, None)
        }
        Some(SupportedCurve::P384) => {
            let key: p384::ecdsa::VerifyingKey =
                x5chain.end_entity_public_key().map_err(key_error)?;
            cose_sign1.verify::<_, p384::ecdsa::Signature>(&key, None, None)
        }
        None => {
            return Err(StatusListError::Signature(
                "the signer key is not on P-256 or P-384".into(),
            ))
        }
    };
    result.into_result().map_err(StatusListError::Signature)
}

/// COSE header parameter `typ` (RFC 9596).
const TYP_HEADER_LABEL: i64 = 16;

fn protected_header(cose_sign1: &CoseSign1, label: i64) -> Option<&Value> {
    cose_sign1
        .protected
        .header
        .rest
        .iter()
        .find(|(l, _)| *l == Label::Int(label))
        .map(|(_, value)| value)
}

/// Move the value of `key` out of `map`. Unknown keys stay in `map` and are ignored.
///
/// Moving, not borrowing, lets `lst` leave the map without a copy.
fn take(map: &mut Vec<(Value, Value)>, key: Value) -> Option<Value> {
    let index = map.iter().position(|(k, _)| *k == key)?;
    Some(map.swap_remove(index).1)
}

fn required(
    map: &mut Vec<(Value, Value)>,
    key: Value,
    name: &'static str,
) -> Result<Value, StatusListError> {
    take(map, key).ok_or(StatusListError::MissingClaim(name))
}

fn integer<T: TryFrom<Integer>>(value: Value, name: &'static str) -> Result<T, StatusListError> {
    value
        .into_integer()
        .ok()
        .and_then(|i| T::try_from(i).ok())
        .ok_or(StatusListError::MalformedClaim(name))
}

/// Whole seconds only. RFC 8392 also allows a float NumericDate, which is refused.
fn timestamp(value: Value, name: &'static str) -> Result<OffsetDateTime, StatusListError> {
    OffsetDateTime::from_unix_timestamp(integer(value, name)?)
        .map_err(|_| StatusListError::MalformedClaim(name))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusListError {
    #[error("the status list token is malformed: {0}")]
    MalformedToken(String),
    #[error("the certificate of the MSO status list is malformed: {0}")]
    MalformedCertificate(String),
    #[error("the status list token does not have the type {STATUS_LIST_CWT_TYPE}")]
    WrongType,
    #[error("the status list token has no {0} claim")]
    MissingClaim(&'static str),
    #[error("the {0} claim of the status list token is malformed")]
    MalformedClaim(&'static str),
    #[error("the status list token has no x5chain in its protected header")]
    MissingX5Chain,
    #[error("the x5chain of the status list token is malformed: {0}")]
    MalformedX5Chain(String),
    #[error("the signature of the status list token is not valid: {0}")]
    Signature(String),
    /// The chain does not reach the trust point, or a certificate in it is not valid or is
    /// revoked.
    #[error("the status list signer is not trusted: {}", .0.join("; "))]
    UntrustedSigner(Vec<String>),
    #[error("the status list token is for {found}, not for {expected}")]
    SubjectMismatch { expected: String, found: String },
    #[error("the status list token expired at {0}")]
    Expired(OffsetDateTime),
    #[error("the status list token could not be fetched from {uri}: {detail}")]
    Fetch { uri: String, detail: String },
    /// The `()` fetcher: the reader does not check the MSO status.
    #[error("MSO status checking is disabled (no status list fetcher configured)")]
    NotSupported,
    /// 1, 2, 4 or 8 bits per status:
    /// <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html#name-status-list>.
    #[error("invalid status size: {0} bits")]
    InvalidBits(u8),
    #[error("index {0} is out of bounds of the status list")]
    IndexOutOfRange(u64),
    #[error("the status list could not be decompressed: {0}")]
    Decompression(String),
}

/// Read the status at `idx` from a zlib-compressed status list (the `lst` claim).
///
/// Only the bytes up to the one that holds `idx` are decompressed. The zlib trailer
/// (Adler-32) is then never read, so it is not checked: the signature of the Status List
/// Token protects `lst`, and Adler-32 is not a security check anyway.
pub fn compressed_status_at(lst: &[u8], bits: u8, idx: u64) -> Result<u8, StatusListError> {
    let len = idx
        .checked_mul(u64::from(bits))
        .and_then(|bit_position| (bit_position / 8).checked_add(1))
        .ok_or(StatusListError::IndexOutOfRange(idx))?;

    // No `with_capacity(len)`: `len` comes from `idx`, not from the list, so the buffer
    // grows only as far as the list really decompresses. A short list leaves `prefix`
    // short, and `status_at` reports the index as out of range.
    let mut prefix = Vec::new();
    ZlibDecoder::new(lst)
        .take(len)
        .read_to_end(&mut prefix)
        .map_err(|e| StatusListError::Decompression(e.to_string()))?;

    status_at(&prefix, bits, idx)
}

/// Read the status at `idx` from a decompressed status list.
///
/// Statuses are packed `bits` at a time, starting at the least significant bit of the first
/// byte: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html#name-compressed-byte-array>.
pub fn status_at(lst: &[u8], bits: u8, idx: u64) -> Result<u8, StatusListError> {
    if !matches!(bits, 1 | 2 | 4 | 8) {
        return Err(StatusListError::InvalidBits(bits));
    }

    let bit_position = idx
        .checked_mul(u64::from(bits))
        .ok_or(StatusListError::IndexOutOfRange(idx))?;

    let byte =
        usize::try_from(bit_position / 8).map_err(|_| StatusListError::IndexOutOfRange(idx))?;

    let shift = bit_position % 8;

    let value = *lst.get(byte).ok_or(StatusListError::IndexOutOfRange(idx))?;

    let mask = ((1u16 << bits) - 1) as u8;

    Ok((value >> shift) & mask)
}

#[cfg(test)]
mod tests;
