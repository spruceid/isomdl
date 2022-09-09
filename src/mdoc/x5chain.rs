use anyhow::{anyhow, Result};
use aws_nitro_enclaves_cose::crypto::SignatureAlgorithm;
use openssl::x509::{X509Ref, X509VerifyResult, X509};
use serde_cbor::Value as CborValue;
use std::{fs::File, io::Read};

#[derive(Debug, Clone)]
pub struct X5Chain(Vec<X509>);

impl From<Vec<X509>> for X5Chain {
    fn from(v: Vec<X509>) -> Self {
        Self(v)
    }
}

impl AsRef<Vec<X509>> for X5Chain {
    fn as_ref(&self) -> &Vec<X509> {
        &self.0
    }
}

impl std::ops::Deref for X5Chain {
    type Target = Vec<X509>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl X5Chain {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn into_cbor(&self) -> Result<CborValue> {
        self.0
            .iter()
            .map(|x509| x509.to_der())
            .map(|result| Ok(CborValue::Bytes(result?)))
            .collect::<Result<Vec<CborValue>>>()
            .map(CborValue::Array)
    }

    pub fn key_algorithm(&self) -> Result<SignatureAlgorithm> {
        // Safe to index into chain, as we know there is at least one element from Builder::build.
        Ok(
            match X509Ref::public_key(&self[0])?
                .ec_key()?
                .group()
                .curve_name()
                .ok_or_else(|| anyhow!("no curve name found on first X509 cert in chain"))?
            {
                openssl::nid::Nid::ECDSA_WITH_SHA256 => SignatureAlgorithm::ES256,
                openssl::nid::Nid::ECDSA_WITH_SHA384 => SignatureAlgorithm::ES384,
                openssl::nid::Nid::ECDSA_WITH_SHA512 => SignatureAlgorithm::ES512,
                nid => {
                    if let Ok(name) = nid.long_name() {
                        Err(anyhow!("unsupported algorithm: {}", name))?
                    }
                    Err(anyhow!(
                        "unsupported algorithm: {:?} (see openssl::nid)",
                        nid
                    ))?
                }
            },
        )
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
        Ok(self)
    }
    pub fn with_der(mut self, s: &str) -> Result<Builder> {
        let cert: X509 = X509::from_der(s.as_bytes())?;
        self.certs.push(cert);
        Ok(self)
    }
    pub fn with_pem_from_file(mut self, mut f: File) -> Result<Builder> {
        let mut bytes_vec: Vec<u8> = vec![];
        f.read_to_end(&mut bytes_vec)?;
        let cert: X509 = X509::from_pem(bytes_vec.as_ref())?;
        self.certs.push(cert);
        Ok(self)
    }
    pub fn with_der_from_file(mut self, mut f: File) -> Result<Builder> {
        let mut bytes_vec: Vec<u8> = vec![];
        f.read_to_end(&mut bytes_vec)?;
        let cert: X509 = X509::from_der(bytes_vec.as_ref())?;
        self.certs.push(cert);
        Ok(self)
    }
    pub fn build(self) -> Result<X5Chain> {
        let mut iter = self.certs.iter();
        let mut first: &X509 = iter.next().ok_or(anyhow!(
            "at least one certificate must be given to the builder"
        ))?;
        for (current_subject, second) in (0_u8..).zip(iter) {
            if second.issued(first) != X509VerifyResult::OK {
                return Err(anyhow!(
                    "x5chain invalid: certificate {} did not issue certificate {}",
                    current_subject + 1,
                    current_subject
                ));
            }
            first = second;
        }
        Ok(self.certs.into())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn test_get_signing_algorithm() {
        static IGCA_PEM: &str = "./test.pem";
        let x5chain = std::fs::read(IGCA_PEM).expect("Could not read file");
        let x5chain_copy = x5chain.clone();
        let x5chain_string = match std::str::from_utf8(&x5chain_copy) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        let issuerx5chain = X5Chain::from(vec![x5chain]);
        todo!()
    }
}
