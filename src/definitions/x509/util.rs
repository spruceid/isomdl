use anyhow::{Context, Error};
use const_oid::{db::rfc4519::COMMON_NAME, AssociatedOid, ObjectIdentifier};
use der::{
    asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef},
    referenced::OwnedToRef,
    Tag, Tagged,
};
use ecdsa::{PrimeCurve, VerifyingKey};
use elliptic_curve::{
    sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey,
};
use p256::NistP256;
use p384::NistP384;
use sec1::point::ModulusSize;
use x509_cert::{attr::AttributeValue, Certificate};

/// Get the public key from a certificate for verification.
pub fn public_key<C>(certificate: &Certificate) -> Result<VerifyingKey<C>, Error>
where
    C: AssociatedOid + CurveArithmetic + PrimeCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    certificate
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref()
        .try_into()
        .map(|key: PublicKey<C>| key.into())
        .context("could not parse public key from PKCS8 SPKI")
}

/// Extract the curve OID from a certificate's subject public key info.
///
/// Returns `None` if the algorithm parameters are missing or cannot be parsed as an OID.
pub fn curve_oid(certificate: &Certificate) -> Option<ObjectIdentifier> {
    let params = certificate
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .parameters
        .as_ref()?;
    // The parameters field contains a DER-encoded ObjectIdentifier.
    // We need to decode it from the full DER encoding (tag+length+value).
    params.decode_as::<ObjectIdentifier>().ok()
}

/// Supported elliptic curves for X.509 verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedCurve {
    P256,
    P384,
}

impl SupportedCurve {
    /// Determine the curve type from a certificate's public key.
    pub fn from_certificate(certificate: &Certificate) -> Option<Self> {
        let oid = curve_oid(certificate)?;
        if oid == NistP256::OID {
            Some(SupportedCurve::P256)
        } else if oid == NistP384::OID {
            Some(SupportedCurve::P384)
        } else {
            None
        }
    }

    /// Determine the curve type from a JWK "crv" parameter value.
    pub fn from_jwk_crv(crv: &str) -> Option<Self> {
        match crv {
            "P-256" => Some(SupportedCurve::P256),
            "P-384" => Some(SupportedCurve::P384),
            _ => None,
        }
    }
}

/// Get the first CommonName of the X.509 certificate, or return "Unknown".
pub fn common_name_or_unknown(certificate: &Certificate) -> &str {
    common_name(certificate).unwrap_or("Unknown")
}

fn common_name(certificate: &Certificate) -> Option<&str> {
    certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter_map(|attribute| {
            if attribute.oid == COMMON_NAME {
                attribute_value_to_str(&attribute.value)
            } else {
                None
            }
        })
        .next()
}

pub fn attribute_value_to_str(av: &AttributeValue) -> Option<&str> {
    match av.tag() {
        Tag::PrintableString => PrintableStringRef::try_from(av).ok().map(|s| s.as_str()),
        Tag::Utf8String => Utf8StringRef::try_from(av).ok().map(|s| s.as_str()),
        Tag::Ia5String => Ia5StringRef::try_from(av).ok().map(|s| s.as_str()),
        Tag::TeletexString => TeletexStringRef::try_from(av).ok().map(|s| s.as_str()),
        _ => None,
    }
}
