//! This module provides functionality for working with `X.509`` certificate chains.
//!
//! The [X5Chain] struct represents a chain of `X.509`` certificates. It can be built using
//! the [Builder] struct, which allows adding certificates in either `PEM`` or `DER`` format.
//! The resulting [X5Chain] can be converted to `CBOR`` format using the [X5Chain::into_cbor] method.
//!
//! # Examples
//!
//! ```ignore
//! use crate::isomdl::issuance::x5chain::{X5Chain, Builder};
//!
//! // Create an X5Chain using the Builder
//! let pem_data = include_bytes!("../../test/issuance/256-cert.pem");
//! let x5chain = X5Chain::builder()
//!     .with_pem(&pem_data)
//!     .expect("Failed to add certificate")
//!     .build()
//!     .expect("Failed to build X5Chain");
//!
//! // Convert the X5Chain to CBOR format
//! let cbor_value = x5chain.into_cbor();
//! ```
//!
//! The [Builder] struct provides methods for adding certificates to the chain. Certificates can be added
//! either from PEM or DER data, or from files containing PEM or DER data.
//!
//! # Examples
//!
//! ```ignore
//! use std::fs::File;
//! use crate::isomdl::issuance::x5chain::Builder;
//!
//! // Create a Builder and add a certificate from PEM data
//! let pem_data = include_bytes!("../../test/issuance/256-cert.pem");
//! let builder = Builder::default()
//!     .with_pem(pem_data)
//!     .expect("Failed to add certificate");
//!
//! // Add a certificate from DER data
//! let der_data = include_bytes!("../../test/issuance/256-cert.der");
//! let builder = builder.with_der(der_data)
//!     .expect("Failed to add certificate");
//!
//! // Add a certificate from a PEM file
//! let pem_file = File::open("256-cert.pem").unwrap();
//! let builder = builder.with_pem_from_file(pem_file)
//!     .expect("Failed to add certificate");
//!
//! // Add a certificate from a DER file
//! let der_file = File::open("256-cert.der").unwrap();
//! let builder = builder.with_der_from_file(der_file)
//!     .expect("Failed to add certificate");
//!
//! // Build the X5Chain
//! let x5chain = builder.build()
//!     .expect("Failed to build X5Chain");
//! ```
//!
//! The [X5Chain] struct also provides a [X5Chain::builder] method for creating a new [Builder] instance.
use crate::definitions::helpers::NonEmptyVec;
use anyhow::{anyhow, Result};
use serde_cbor::Value as CborValue;
use std::{fs::File, io::Read};
use x509_cert::{
    certificate::Certificate,
    der::{Decode, Encode},
};

pub const X5CHAIN_HEADER_LABEL: i128 = 33;

/// Represents an X509 certificate.
#[derive(Debug, Clone)]
pub struct X509 {
    bytes: Vec<u8>,
}

/// Represents a chain of [X509] certificates.
#[derive(Debug, Clone)]
pub struct X5Chain(NonEmptyVec<X509>);

impl From<NonEmptyVec<X509>> for X5Chain {
    fn from(v: NonEmptyVec<X509>) -> Self {
        Self(v)
    }
}

/// Implements the [X5Chain] struct.
///
/// This struct provides methods for building and converting the X5Chain object.
impl X5Chain {
    /// Creates a new [Builder] instance for [X5Chain].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Converts the [X5Chain] object into a [CborValue].
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
}

/// Builder for creating an [X5Chain].
///
/// This struct is used to build an [X5Chain] by providing a vector of [X509] certificates.  
/// The [X5Chain] represents a chain of `X.509`` certificates used for issuance.
///
/// # Note
///
/// The `Builder` struct is typically used in the context of the `issuance` module.
#[derive(Default, Debug, Clone)]
pub struct Builder {
    certs: Vec<X509>,
}

impl Builder {
    /// Adds a `PEM-encoded`` certificate to the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the `PEM`` cannot be parsed or the certificate
    /// cannot be converted to bytes.
    ///
    /// # Returns
    ///
    /// Returns a [Result] containing the updated [Builder] if successful.
    pub fn with_pem(mut self, data: &[u8]) -> Result<Builder> {
        let bytes = pem_rfc7468::decode_vec(data)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))?
            .1;
        let cert: Certificate = Certificate::from_der(&bytes)
            .map_err(|e| anyhow!("unable to parse certificate from der: {}", e))?;
        let x509 = X509 {
            bytes: cert
                .to_vec()
                .map_err(|e| anyhow!("unable to convert certificate to bytes: {}", e))?,
        };
        self.certs.push(x509);
        Ok(self)
    }

    /// Adds a `DER`-encoded certificate to the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate cannot be parsed from `DER` encoding
    /// or cannot be converted to bytes.
    ///
    /// # Returns
    ///
    /// Returns a [Result] containing the updated [Builder] if successful.
    pub fn with_der(mut self, data: &[u8]) -> Result<Builder> {
        let cert: Certificate = Certificate::from_der(data)
            .map_err(|e| anyhow!("unable to parse certificate from der encoding: {}", e))?;
        let x509 = X509 {
            bytes: cert
                .to_vec()
                .map_err(|e| anyhow!("unable to convert certificate to bytes: {}", e))?,
        };
        self.certs.push(x509);
        Ok(self)
    }

    /// Adds a `PEM`-encoded certificate from a file to the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the certificate cannot be parsed or converted to bytes.
    ///
    /// # Returns
    ///
    /// Returns a [Result] containing the updated [Builder] if successful.
    pub fn with_pem_from_file(self, mut f: File) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        f.read_to_end(&mut data)?;
        self.with_pem(&data)
    }

    /// Adds a `DER`-encoded certificate from a file to the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the certificate cannot be parsed or converted to bytes.
    ///
    /// # Returns
    ///
    /// Returns a [Result] containing the updated [Builder] if successful.
    pub fn with_der_from_file(self, mut f: File) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        f.read_to_end(&mut data)?;
        self.with_der(&data)
    }

    /// Builds the [X5Chain] from the added certificates.
    ///
    /// # Errors
    ///
    /// Returns an error if at least one certificate is not added to the builder.
    ///
    /// # Returns
    ///
    /// Returns a [Result] containing the built [X5Chain] if successful.
    pub fn build(self) -> Result<X5Chain> {
        Ok(X5Chain(self.certs.try_into().map_err(|_| {
            anyhow!("at least one certificate must be given to the builder")
        })?))
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
        let _x5chain = X5Chain::builder()
            .with_pem(CERT_256)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");

        //let self_signed = &x5chain[0];

        //assert!(self_signed.issued(self_signed) == CertificateVerifyResult::OK);
        //assert!(self_signed
        //    .verify(
        //        &self_signed
        //            .public_key()
        //            .expect("unable to get public key of cert")
        //    )
        //    .expect("unable to verify public key of cert"));

        //assert!(matches!(
        //    x5chain
        //        .key_algorithm()
        //        .expect("unable to retrieve public key algorithm"),
        //    Algorithm::ES256
        //));
    }

    #[test]
    pub fn self_signed_es384() {
        let _x5chain = X5Chain::builder()
            .with_pem(CERT_384)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");

        //let self_signed = &x5chain[0];

        //assert!(self_signed.issued(self_signed) == CertificateVerifyResult::OK);
        //assert!(self_signed
        //    .verify(
        //        &self_signed
        //            .public_key()
        //            .expect("unable to get public key of cert")
        //    )
        //    .expect("unable to verify public key of cert"));

        //assert!(matches!(
        //    x5chain
        //        .key_algorithm()
        //        .expect("unable to retrieve public key algorithm"),
        //    Algorithm::ES384
        //));
    }

    #[test]
    pub fn self_signed_es512() {
        let _x5chain = X5Chain::builder()
            .with_pem(CERT_521)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");

        //let self_signed = &x5chain[0];

        //assert!(self_signed.issued(self_signed) == CertificateVerifyResult::OK);
        //assert!(self_signed
        //    .verify(
        //        &self_signed
        //            .public_key()
        //            .expect("unable to get public key of cert")
        //    )
        //    .expect("unable to verify public key of cert"));

        //assert!(matches!(
        //    x5chain
        //        .key_algorithm()
        //        .expect("unable to retrieve public key algorithm"),
        //    Algorithm::ES512
        //));
    }
}
