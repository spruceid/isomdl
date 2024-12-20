use anyhow::Error;
use der::{DecodePem, EncodePem};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

/// A collection of roots of trust, each with a specific purpose.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TrustAnchorRegistry {
    /// The roots of trust in this registry.
    pub anchors: Vec<TrustAnchor>,
}

/// A root of trust for a specific purpose.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub certificate: Certificate,
    pub purpose: TrustPurpose,
}

/// Identifies what purpose the certificate is trusted for.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustPurpose {
    /// Issuer Authority Certificate Authority as defined in 18013-5.
    Iaca,
    /// Reader Certificate Authority as defined in 18013-5.
    ReaderCa,
}

/// PEM representation of a TrustAnchor, used for serialization and deserialization only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PemTrustAnchor {
    pub certificate_pem: String,
    pub purpose: TrustPurpose,
}

impl TrustAnchorRegistry {
    /// Build a trust anchor registry from PEM certificates.
    pub fn from_pem_certificates(certs: Vec<PemTrustAnchor>) -> Result<Self, Error> {
        Ok(Self {
            anchors: certs
                .into_iter()
                .map(TrustAnchor::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl<'l> TryFrom<&'l TrustAnchor> for PemTrustAnchor {
    type Error = Error;

    fn try_from(value: &'l TrustAnchor) -> Result<Self, Self::Error> {
        Ok(Self {
            certificate_pem: value.certificate.to_pem(Default::default())?,
            purpose: value.purpose,
        })
    }
}

impl TryFrom<PemTrustAnchor> for TrustAnchor {
    type Error = Error;

    fn try_from(value: PemTrustAnchor) -> Result<Self, Self::Error> {
        Ok(Self {
            certificate: Certificate::from_pem(&value.certificate_pem)?,
            purpose: value.purpose,
        })
    }
}

impl Serialize for TrustAnchor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;

        PemTrustAnchor::try_from(self)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TrustAnchor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        PemTrustAnchor::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
}
