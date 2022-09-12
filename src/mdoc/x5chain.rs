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
                openssl::nid::Nid::X9_62_PRIME256V1 => SignatureAlgorithm::ES256,
                openssl::nid::Nid::SECP384R1 => SignatureAlgorithm::ES384,
                openssl::nid::Nid::SECP521R1 => SignatureAlgorithm::ES512,
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
    pub fn with_pem(mut self, s: &[u8]) -> Result<Builder> {
        let cert: X509 = X509::from_pem(s)?;
        self.certs.push(cert);
        Ok(self)
    }
    pub fn with_der(mut self, s: &[u8]) -> Result<Builder> {
        let cert: X509 = X509::from_der(s)?;
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
        let mut first: &X509 = iter
            .next()
            .ok_or_else(|| anyhow!("at least one certificate must be given to the builder"))?;
        for (current_subject, second) in (0_u8..).zip(iter) {
            if second.issued(first) != X509VerifyResult::OK
                || !second
                    .verify(
                        first
                            .public_key()
                            .map_err(|e| anyhow!("unable to get public key of certificate: {}", e))?
                            .as_ref(),
                    )
                    .map_err(|e| anyhow!("unable to verify signature of certificate: {}", e))?
            {
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
pub mod test {
    use super::*;

    static CERT_256: &[u8] = include_bytes!("../../test/issuance/256-cert.pem");
    static CERT_384: &[u8] = include_bytes!("../../test/issuance/384-cert.pem");
    static CERT_521: &[u8] = include_bytes!("../../test/issuance/521-cert.pem");

    #[test]
    pub fn self_signed_es256() {
        let x5chain = X5Chain::builder()
            .with_pem(CERT_256)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");

        let self_signed = &x5chain[0];

        assert!(self_signed.issued(self_signed) == X509VerifyResult::OK);
        assert!(self_signed
            .verify(
                &self_signed
                    .public_key()
                    .expect("unable to get public key of cert")
            )
            .expect("unable to verify public key of cert"));

        assert!(match x5chain
            .key_algorithm()
            .expect("unable to retrieve public key algorithm")
        {
            SignatureAlgorithm::ES256 => true,
            _ => false,
        });
    }

    #[test]
    pub fn self_signed_es384() {
        let x5chain = X5Chain::builder()
            .with_pem(CERT_384)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");

        let self_signed = &x5chain[0];

        assert!(self_signed.issued(self_signed) == X509VerifyResult::OK);
        assert!(self_signed
            .verify(
                &self_signed
                    .public_key()
                    .expect("unable to get public key of cert")
            )
            .expect("unable to verify public key of cert"));

        assert!(match x5chain
            .key_algorithm()
            .expect("unable to retrieve public key algorithm")
        {
            SignatureAlgorithm::ES384 => true,
            _ => false,
        });
    }

    #[test]
    pub fn self_signed_es512() {
        let x5chain = X5Chain::builder()
            .with_pem(CERT_521)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");

        let self_signed = &x5chain[0];

        assert!(self_signed.issued(self_signed) == X509VerifyResult::OK);
        assert!(self_signed
            .verify(
                &self_signed
                    .public_key()
                    .expect("unable to get public key of cert")
            )
            .expect("unable to verify public key of cert"));

        assert!(match x5chain
            .key_algorithm()
            .expect("unable to retrieve public key algorithm")
        {
            SignatureAlgorithm::ES512 => true,
            _ => false,
        });
    }
}
