use std::io::Read;

use crate::definitions::helpers::NonEmptyVec;

use anyhow::{anyhow, bail, Context, Error, Result};

use const_oid::AssociatedOid;

use ciborium::Value as CborValue;
use ecdsa::{PrimeCurve, VerifyingKey};
use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize,
};
use x509_cert::der::Encode;
use x509_cert::{certificate::Certificate, der::Decode};

use super::util::{common_name_or_unknown, public_key};

/// See: <https://www.iana.org/assignments/cose/cose.xhtml#header-parameters>
pub const X5CHAIN_COSE_HEADER_LABEL: i64 = 0x21;

/// X.509 certificate with the DER representation held in memory for ease of serialization.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CertificateWithDer {
    pub inner: Certificate,
    der: Vec<u8>,
}

impl CertificateWithDer {
    pub fn from_pem(bytes: &[u8]) -> Result<Self> {
        let bytes = pem_rfc7468::decode_vec(bytes)
            .map_err(|e| anyhow!("unable to parse certificate from PEM encoding: {e}"))?
            .1;
        CertificateWithDer::from_der(&bytes)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let inner = Certificate::from_der(bytes)
            .context("unable to parse certificate from DER encoding")?;
        Ok(Self {
            inner,
            der: bytes.to_vec(),
        })
    }

    pub fn from_cert(certificate: Certificate) -> Result<Self> {
        let der = certificate.to_der()?;
        Ok(Self {
            inner: certificate,
            der,
        })
    }
}

#[derive(Debug, Clone)]
pub struct X5Chain(NonEmptyVec<CertificateWithDer>);

impl From<NonEmptyVec<CertificateWithDer>> for X5Chain {
    fn from(v: NonEmptyVec<CertificateWithDer>) -> Self {
        Self(v)
    }
}

impl X5Chain {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn into_cbor(&self) -> CborValue {
        match &self.0.as_ref() {
            &[cert] => CborValue::Bytes(cert.der.clone()),
            certs => CborValue::Array(
                certs
                    .iter()
                    .map(|x509| x509.der.clone())
                    .map(CborValue::Bytes)
                    .collect::<Vec<CborValue>>(),
            ),
        }
    }

    pub fn from_cbor(cbor: CborValue) -> Result<Self, Error> {
        match cbor {
            CborValue::Bytes(bytes) => {
                Self::builder().with_der_certificate(&bytes)?.build()
            },
            CborValue::Array(x509s) => {
                x509s.iter()
                    .try_fold(Self::builder(), |mut builder, x509| match x509 {
                        CborValue::Bytes(bytes) => {
                            builder = builder.with_der_certificate(bytes)?;
                            Ok(builder)
                        },
                        _ => bail!("expected x509 certificate in the x5chain to be a cbor encoded bytestring, but received: {x509:?}")
                    })?
                    .build()
            },
            _ => bail!("expected x5chain to be a cbor encoded bytestring or array, but received: {cbor:?}")
        }
    }

    /// Retrieve the end-entity certificate.
    pub fn end_entity_certificate(&self) -> &Certificate {
        &self.0[0].inner
    }

    /// Retrieve the public key of the end-entity certificate.
    pub fn end_entity_public_key<C>(&self) -> Result<VerifyingKey<C>, Error>
    where
        C: AssociatedOid + CurveArithmetic + PrimeCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        public_key(self.end_entity_certificate())
    }

    /// Retrieve the public key of the end-entity certificate.
    pub fn end_entity_common_name(&self) -> &str {
        common_name_or_unknown(self.end_entity_certificate())
    }

    /// Retrieve the root-entity certificate.
    pub fn root_entity_certificate(&self) -> &Certificate {
        &self.0.last().inner
    }

    /// Retrieve the public key of the root-entity certificate.
    pub fn root_entity_public_key<C>(&self) -> Result<VerifyingKey<C>, Error>
    where
        C: AssociatedOid + CurveArithmetic + PrimeCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        public_key(self.root_entity_certificate())
    }

    /// Retrieve the public key of the root-entity certificate.
    pub fn root_entity_common_name(&self) -> &str {
        common_name_or_unknown(self.root_entity_certificate())
    }

    /// Iterate over the certificates in the chain.
    pub fn iter(&self) -> impl Iterator<Item = &CertificateWithDer> {
        self.0.iter()
    }
}

#[derive(Default, Debug, Clone)]
pub struct Builder {
    certs: Vec<CertificateWithDer>,
}

impl Builder {
    pub fn with_certificate(mut self, cert: Certificate) -> Result<Builder> {
        let x509 = CertificateWithDer::from_cert(cert)?;
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_certificate_and_der(mut self, x509: CertificateWithDer) -> Builder {
        self.certs.push(x509);
        self
    }
    pub fn with_pem_certificate(mut self, data: &[u8]) -> Result<Builder> {
        let x509 = CertificateWithDer::from_pem(data)?;
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_der_certificate(mut self, data: &[u8]) -> Result<Builder> {
        let x509 = CertificateWithDer::from_der(data)?;
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_pem_certificate_from_io<R: Read>(self, mut io: R) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        io.read_to_end(&mut data)?;
        self.with_pem_certificate(&data)
    }
    pub fn with_der_certificate_from_io<R: Read>(self, mut io: R) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        io.read_to_end(&mut data)?;
        self.with_der_certificate(&data)
    }
    pub fn build(self) -> Result<X5Chain> {
        Ok(X5Chain(self.certs.try_into().context(
            "at least one certificate must be given to the builder",
        )?))
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
            .with_pem_certificate(CERT_256)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
    }

    #[test]
    pub fn self_signed_es384() {
        let _x5chain = X5Chain::builder()
            .with_pem_certificate(CERT_384)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
    }

    #[test]
    pub fn self_signed_es512() {
        let _x5chain = X5Chain::builder()
            .with_pem_certificate(CERT_521)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
    }
}
