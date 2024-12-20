use anyhow::{Context, Error};
use const_oid::{db::rfc4519::COMMON_NAME, AssociatedOid};
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
