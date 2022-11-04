use crate::definitions::helpers::NonEmptyVec;
use anyhow::{anyhow, Result};
use cose_rs::algorithm::Algorithm;
use serde_cbor::Value as CborValue;
use std::{fs::File, io::Read};
use x509_cert::{certificate::Certificate, der::{Encode, Decode, PemReader, Reader}};

// Temporarily registered, possibly subject to change.
pub const X5CHAIN_HEADER_LABEL: i128 = 33;

#[derive(Debug, Clone)]
pub struct X509 {
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct X5Chain(NonEmptyVec<X509>);

impl From<NonEmptyVec<X509>> for X5Chain {
    fn from(v: NonEmptyVec<X509>) -> Self {
        Self(v)
    }
}

//impl AsRef<[Certificate<'static>]> for X5Chain {
//    fn as_ref(&self) -> &[Certificate] {
//        self.0.as_ref()
//    }
//}

impl X5Chain {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn into_cbor(&self) -> CborValue {
        CborValue::Array(self.0
            .iter()
            .cloned()
            .map(|x509| x509.bytes)
            .map(CborValue::Bytes)
            .collect::<Vec<CborValue>>())
            
    }

    pub fn key_algorithm(&self) -> Result<Algorithm> {
        // Safe to index into chain, as we know there is at least one element from Builder::build.
        Ok(
            todo!()
            //match CertificateRef::public_key(&self[0])?
            //    .ec_key()?
            //    .group()
            //    .curve_name()
            //    .ok_or_else(|| anyhow!("no curve name found on first Certificate cert in chain"))?
            //{
            //    openssl::nid::Nid::X9_62_PRIME256V1 => Algorithm::ES256,
            //    openssl::nid::Nid::SECP384R1 => Algorithm::ES384,
            //    openssl::nid::Nid::SECP521R1 => Algorithm::ES512,
            //    nid => {
            //        if let Ok(name) = nid.long_name() {
            //            Err(anyhow!("unsupported algorithm: {}", name))?
            //        }
            //        Err(anyhow!(
            //            "unsupported algorithm: {:?} (see openssl::nid)",
            //            nid
            //        ))?
            //    }
            //},
        )
    }
}

#[derive(Default, Debug, Clone)]
pub struct Builder {
    certs: Vec<X509>,
}

impl Builder {
    pub fn with_pem(mut self, data: Vec<u8>) -> Result<Builder> {
        let cert: Certificate = PemReader::new(&data)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))?
            .decode()
            .map_err(|e| anyhow!("unable to parse certificate from pem encoding: {}", e))?;
        let x509 = X509 { bytes: cert.to_vec().map_err(|e| anyhow!("unable to convert certificate to bytes: {}", e))? };
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_der(mut self, data: Vec<u8>) -> Result<Builder> {
        let cert: Certificate = Certificate::from_der(&data)
            .map_err(|e| anyhow!("unable to parse certificate from der encoding: {}", e))?;
        let x509 = X509 { bytes: cert.to_vec().map_err(|e| anyhow!("unable to convert certificate to bytes: {}", e))? };
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_pem_from_file(mut self, mut f: File) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        f.read_to_end(&mut data)?;
        let cert: Certificate = PemReader::new(&data)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))?
            .decode()
            .map_err(|e| anyhow!("unable to parse certificate from pem file: {}", e))?;
        let x509 = X509 { bytes: cert.to_vec().map_err(|e| anyhow!("unable to convert certificate to bytes: {}", e))? };
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_der_from_file(mut self, mut f: File) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        f.read_to_end(&mut data)?;
        let cert: Certificate = Certificate::from_der(&data)
            .map_err(|e| anyhow!("unable to parse certificate from der file: {}", e))?;
        let x509 = X509 { bytes: cert.to_vec().map_err(|e| anyhow!("unable to convert certificate to bytes: {}", e))? };
        self.certs.push(x509);
        Ok(self)
    }
    pub fn build(self) -> Result<X5Chain> {
        // TODO: Add chain validation
        Ok(X5Chain(self.certs.try_into()
            .map_err(|_| anyhow!("at least one certificate must be given to the builder"))?))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    static CERT_256: &[u8] = include_bytes!("../../test/issuance/256-cert.pem");
    static CERT_384: &[u8] = include_bytes!("../../test/issuance/384-cert.pem");
    static CERT_521: &[u8] = include_bytes!("../../test/issuance/521-cert.pem");

    //#[test]
    //pub fn self_signed_es256() {
    //    let x5chain = X5Chain::builder()
    //        .with_pem(CERT_256)
    //        .expect("unable to add cert")
    //        .build()
    //        .expect("unable to build x5chain");

    //    let self_signed = &x5chain[0];

    //    assert!(self_signed.issued(self_signed) == CertificateVerifyResult::OK);
    //    assert!(self_signed
    //        .verify(
    //            &self_signed
    //                .public_key()
    //                .expect("unable to get public key of cert")
    //        )
    //        .expect("unable to verify public key of cert"));

    //    assert!(matches!(
    //        x5chain
    //            .key_algorithm()
    //            .expect("unable to retrieve public key algorithm"),
    //        Algorithm::ES256
    //    ));
    //}

    //#[test]
    //pub fn self_signed_es384() {
    //    let x5chain = X5Chain::builder()
    //        .with_pem(CERT_384)
    //        .expect("unable to add cert")
    //        .build()
    //        .expect("unable to build x5chain");

    //    let self_signed = &x5chain[0];

    //    assert!(self_signed.issued(self_signed) == CertificateVerifyResult::OK);
    //    assert!(self_signed
    //        .verify(
    //            &self_signed
    //                .public_key()
    //                .expect("unable to get public key of cert")
    //        )
    //        .expect("unable to verify public key of cert"));

    //    assert!(matches!(
    //        x5chain
    //            .key_algorithm()
    //            .expect("unable to retrieve public key algorithm"),
    //        Algorithm::ES384
    //    ));
    //}

    //#[test]
    //pub fn self_signed_es512() {
    //    let x5chain = X5Chain::builder()
    //        .with_pem(CERT_521)
    //        .expect("unable to add cert")
    //        .build()
    //        .expect("unable to build x5chain");

    //    let self_signed = &x5chain[0];

    //    assert!(self_signed.issued(self_signed) == CertificateVerifyResult::OK);
    //    assert!(self_signed
    //        .verify(
    //            &self_signed
    //                .public_key()
    //                .expect("unable to get public key of cert")
    //        )
    //        .expect("unable to verify public key of cert"));

    //    assert!(matches!(
    //        x5chain
    //            .key_algorithm()
    //            .expect("unable to retrieve public key algorithm"),
    //        Algorithm::ES512
    //    ));
    //}
}
