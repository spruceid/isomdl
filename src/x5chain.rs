use anyhow::{anyhow, Result};
use openssl::x509::{X509Ref, X509VerifyResult, X509};
use serde_cbor::Value as CborValue;
use std::{fs::File, io::Read};

#[derive(Debug, Clone)]
pub struct X5Chain(Vec<Vec<u8>>);

impl From<Vec<Vec<u8>>> for X5Chain {
    fn from(v: Vec<Vec<u8>>) -> Self {
        Self(v)
    }
}

impl AsRef<Vec<Vec<u8>>> for X5Chain {
    fn as_ref(&self) -> &Vec<Vec<u8>> {
        &self.0
    }
}

impl X5Chain {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn into_cbor(self) -> CborValue {
        self.0
            .into_iter()
            .map(CborValue::Bytes)
            .collect::<Vec<CborValue>>()
            .into()
    }
}

#[derive(Default, Debug, Clone)]
pub struct Builder {
    certs: Vec<X509>,
}

impl Builder {
    pub fn with_pem(mut self, s: &str) -> Result<Builder> {
        let cert: X509 = X509::from_pem(s.as_bytes())?;
        self.certs.push(cert);
        return Ok(self);
    }
    pub fn with_der(mut self, s: &str) -> Result<Builder> {
        let cert: X509 = X509::from_der(s.as_bytes())?;
        self.certs.push(cert);
        return Ok(self);
    }
    pub fn with_pem_from_file(mut self, mut f: File) -> Result<Builder> {
        let mut bytes_vec: Vec<u8> = vec![];
        f.read_to_end(&mut bytes_vec)?;
        let cert: X509 = X509::from_pem(bytes_vec.as_ref())?;
        self.certs.push(cert);
        return Ok(self);
    }
    pub fn with_der_from_file(mut self, mut f: File) -> Result<Builder> {
        let mut bytes_vec: Vec<u8> = vec![];
        f.read_to_end(&mut bytes_vec)?;
        let cert: X509 = X509::from_der(bytes_vec.as_ref())?;
        self.certs.push(cert);
        return Ok(self);
    }
    pub fn build(self) -> Result<X5Chain> {
        let mut iter = self.certs.iter();
        let mut first: &X509 = iter.next().ok_or(anyhow!(
            "at least one certificate must be given to the builder"
        ))?;
        let mut current_subject: u8 = 0;
        while let Some(second) = iter.next() {
            if second.issued(&first) != X509VerifyResult::OK {
                return Err(anyhow!(
                    "x5chain invalid: certificate {} did not issue certificate {}",
                    current_subject + 1,
                    current_subject
                ));
            }
            first = second;
            current_subject += 1;
        }
        self.certs
            .iter()
            .map(|cert| cert.to_der())
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
            .map(Into::into)
    }
}
