use crate::definitions::helpers::NonEmptyVec;
use crate::definitions::x509::error::Error as X509Error;
use crate::definitions::x509::trust_anchor::check_validity_period;
use crate::definitions::x509::trust_anchor::find_anchor;
use crate::definitions::x509::trust_anchor::validate_with_trust_anchor;
use crate::definitions::x509::trust_anchor::TrustAnchorRegistry;
use anyhow::{anyhow, Result};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;

use const_oid::AssociatedOid;

use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey,
};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use signature::Verifier;
use std::collections::HashSet;
use std::hash::Hash;
use std::{fs::File, io::Read};
use x509_cert::der::Encode;
use x509_cert::{
    certificate::Certificate,
    der::{referenced::OwnedToRef, Decode},
};

pub const X5CHAIN_HEADER_LABEL: i128 = 33;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct X509 {
    pub bytes: Vec<u8>,
}

impl X509 {
    pub fn public_key<C>(&self) -> Result<PublicKey<C>, X509Error>
    where
        C: AssociatedOid + CurveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let cert = x509_cert::Certificate::from_der(&self.bytes)?;
        cert.tbs_certificate
            .subject_public_key_info
            .owned_to_ref()
            .try_into()
            .map_err(|e| format!("could not parse public key from pkcs8 spki: {e}"))
            .map_err(|_e| {
                X509Error::ValidationError("could not parse public key from pkcs8 spki".to_string())
            })
    }

    pub fn from_pem(bytes: &[u8]) -> Result<Self> {
        let bytes = pem_rfc7468::decode_vec(bytes)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))?
            .1;
        X509::from_der(&bytes)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let cert: Certificate = Certificate::from_der(bytes)
            .map_err(|e| anyhow!("unable to parse certificate from der encoding: {}", e))?;
        Ok(X509 {
            bytes: cert
                .to_der()
                .map_err(|e| anyhow!("unable to convert certificate to bytes: {}", e))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct X5Chain(NonEmptyVec<X509>);

impl From<NonEmptyVec<X509>> for X5Chain {
    fn from(v: NonEmptyVec<X509>) -> Self {
        Self(v)
    }
}

impl X5Chain {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn into_cbor(&self) -> CborValue {
        match &self.0.as_ref() {
            &[cert] => CborValue::Bytes(cert.bytes.clone()),
            certs => CborValue::Array(
                certs
                    .iter()
                    .cloned()
                    .map(|x509| x509.bytes)
                    .map(CborValue::Bytes)
                    .collect::<Vec<CborValue>>(),
            ),
        }
    }

    pub fn from_cbor(cbor_bytes: CborValue) -> Result<Self, X509Error> {
        match cbor_bytes {
            CborValue::Bytes(bytes) => {
                Self::builder().with_der(&bytes).map_err(
                    |e| X509Error::DecodingError(e.to_string())
                )?.build().map_err(
                    |e| X509Error::DecodingError(e.to_string())
                )
            },
            CborValue::Array(x509s) => {
                x509s.iter()
                    .try_fold(Self::builder(), |builder, x509| match x509 {
                        CborValue::Bytes(bytes) => {
                            let builder = builder.with_der(bytes).map_err(
                                |e| X509Error::DecodingError(e.to_string())
                            )?;
                            Ok(builder)
                        },
                        _ => Err(X509Error::ValidationError(format!("Expecting x509 certificate in the x5chain to be a cbor encoded bytestring, but received: {x509:?}")))
                    })?
                     .build()
                    .map_err(|e| X509Error::DecodingError(e.to_string())
                )
            },
            _ => Err(X509Error::ValidationError(format!("Expecting x509 certificate in the x5chain to be a cbor encoded bytestring, but received: {cbor_bytes:?}")))
        }
    }

    pub fn get_signer_key(&self) -> Result<VerifyingKey, X509Error> {
        let signer = match self.0.first() {
            Some(x) => {
                let x509 = x509_cert::Certificate::from_der(&x.bytes)?;

                x509.tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
            }
            _ => return Err(X509Error::CborDecodingError)?,
        };
        Ok(VerifyingKey::from_public_key_der(signer.raw_bytes())?)
    }

    pub fn validate(&self, trust_anchor_registry: Option<TrustAnchorRegistry>) -> Vec<X509Error> {
        let x5chain = self.0.as_ref();
        let mut errors: Vec<X509Error> = vec![];

        if !has_unique_elements(x5chain) {
            errors.push(X509Error::ValidationError(
                "x5chain contains duplicate certificates".to_string(),
            ))
        };

        x5chain.windows(2).for_each(|chain_link| {
            let target = &chain_link[0];
            let issuer = &chain_link[1];
            if check_signature(target, issuer).is_err() {
                errors.push(X509Error::ValidationError(format!(
                    "invalid signature for target: {:?}",
                    target
                )));
            }
        });

        //make sure all submitted certificates are valid
        for x509 in x5chain {
            let cert = x509_cert::Certificate::from_der(&x509.bytes);
            match cert {
                Ok(c) => {
                    errors.append(&mut check_validity_period(&c));
                }
                Err(e) => errors.push(e.into()),
            }
        }

        //validate the last certificate in the chain against trust anchor
        let last_in_chain = x5chain.last();
        if let Some(x509) = last_in_chain {
            match x509_cert::Certificate::from_der(&x509.bytes) {
                Ok(cert) => {
                    // if the issuer of the signer certificate is known in the trust anchor registry, do the validation.
                    // otherwise, report an error and skip.
                    match find_anchor(cert, trust_anchor_registry) {
                        Ok(anchor) => {
                            if let Some(trust_anchor) = anchor {
                                errors.append(&mut validate_with_trust_anchor(
                                    x509.clone(),
                                    trust_anchor,
                                ));
                            } else {
                                errors.push(X509Error::ValidationError(
                                    "No matching trust anchor found".to_string(),
                                ));
                            }
                        }
                        Err(e) => errors.push(e),
                    }
                }
                Err(e) => errors.push(e.into()),
            }
        } else {
            errors.push(X509Error::ValidationError(
                "Empty certificate chain".to_string(),
            ))
        }

        errors
    }
}

pub fn check_signature(target: &X509, issuer: &X509) -> Result<(), X509Error> {
    let parent_public_key = ecdsa::VerifyingKey::from(issuer.public_key()?);
    let child_cert = x509_cert::Certificate::from_der(&target.bytes)?;
    let sig: ecdsa::Signature<NistP256> =
        ecdsa::Signature::from_der(child_cert.signature.raw_bytes())?;
    let bytes = child_cert.tbs_certificate.to_der()?;
    Ok(parent_public_key.verify(&bytes, &sig)?)
}

fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}

#[derive(Default, Debug, Clone)]
pub struct Builder {
    certs: Vec<X509>,
}

impl Builder {
    pub fn with_pem(mut self, data: &[u8]) -> Result<Builder> {
        let x509 = X509::from_pem(data)?;
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_der(mut self, data: &[u8]) -> Result<Builder> {
        let x509 = X509::from_der(data)?;
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_pem_from_file(self, mut f: File) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        f.read_to_end(&mut data)?;
        self.with_pem(&data)
    }
    pub fn with_der_from_file(self, mut f: File) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        f.read_to_end(&mut data)?;
        self.with_der(&data)
    }
    pub fn build(self) -> Result<X5Chain> {
        Ok(X5Chain(self.certs.try_into().map_err(|_| {
            anyhow!("at least one certificate must be given to the builder")
        })?))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    static CERT_256: &[u8] = include_bytes!("../../../test/issuance/256-cert.pem");
    static CERT_384: &[u8] = include_bytes!("../../../test/issuance/384-cert.pem");
    static CERT_521: &[u8] = include_bytes!("../../../test/issuance/521-cert.pem");

    #[test]
    pub fn self_signed_es256() {
        let _x5chain = X5Chain::builder()
            .with_pem(CERT_256)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
    }

    #[test]
    pub fn self_signed_es384() {
        let _x5chain = X5Chain::builder()
            .with_pem(CERT_384)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
    }

    #[test]
    pub fn self_signed_es512() {
        let _x5chain = X5Chain::builder()
            .with_pem(CERT_521)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
    }

    #[test]
    pub fn correct_signature() {
        let target = include_bytes!("../../../test/presentation/isomdl_iaca_signer.pem");
        let issuer = include_bytes!("../../../test/presentation/isomdl_iaca_root_cert.pem");
        check_signature(
            &X509::from_pem(target).unwrap(),
            &X509::from_pem(issuer).unwrap(),
        )
        .expect("issuer did not sign target cert")
    }

    #[test]
    pub fn incorrect_signature() {
        let issuer = include_bytes!("../../../test/presentation/isomdl_iaca_signer.pem");
        let target = include_bytes!("../../../test/presentation/isomdl_iaca_root_cert.pem");
        check_signature(
            &X509::from_pem(target).unwrap(),
            &X509::from_pem(issuer).unwrap(),
        )
        .expect_err("issuer did sign target cert");
    }
}
