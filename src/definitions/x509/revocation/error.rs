//! CRL-specific error types.

/// Result of checking a certificate's revocation status.
#[derive(Debug, Clone)]
pub enum RevocationStatus {
    /// The certificate is not revoked (not found in CRL).
    Valid,
    /// The certificate has been revoked.
    ///
    /// Per ISO 18013-5 B.3.2, a certificate found in the CRL is considered
    /// revoked with status UNSPECIFIED. CRL entry extensions (including reason
    /// codes) are not used per the ISO 18013-5 CRL profile.
    Revoked {
        /// The serial number of the revoked certificate (hex encoded).
        serial: String,
    },
}

/// Errors that can occur during CRL operations.
#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    /// Failed to fetch CRL from a URL.
    #[error("failed to fetch CRL from {url}: {source}")]
    Fetch {
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Failed to parse CRL data.
    #[error("failed to parse CRL: {0}")]
    Parse(#[from] der::Error),

    /// CRL signature verification failed.
    #[error("CRL signature verification failed")]
    SignatureInvalid,

    /// CRL issuer does not match the expected issuer.
    #[error("CRL issuer does not match certificate issuer")]
    IssuerMismatch,

    /// CRL has expired (current time is past nextUpdate).
    #[error("CRL has expired (nextUpdate: {next_update})")]
    Expired { next_update: String },

    /// CRL is not yet valid (current time is before thisUpdate).
    #[error("CRL is not yet valid (thisUpdate: {this_update})")]
    NotYetValid { this_update: String },

    /// CRL contains an unrecognized critical extension.
    #[error("CRL contains unrecognized critical extension: {oid}")]
    UnrecognizedCriticalExtension { oid: String },

    /// No CRL distribution point found in the certificate.
    #[error("no CRL distribution point in certificate")]
    NoDistributionPoint,

    /// All CRL distribution point URLs failed.
    #[error("all CRL distribution point URLs failed: {errors:?}")]
    AllUrlsFailed { errors: Vec<String> },

    /// CRL version is not v2 as required by ISO 18013-5.
    #[error("CRL version is not v2")]
    InvalidVersion,

    /// CRL TBS signature algorithm does not match outer signature algorithm.
    #[error("CRL TBS signature algorithm does not match outer signature algorithm")]
    SignatureAlgorithmMismatch,

    /// CRL is missing the mandatory nextUpdate field.
    #[error("CRL is missing mandatory nextUpdate field")]
    MissingNextUpdate,

    /// CRL has an empty revoked certificates list (shall not be present if empty).
    #[error("CRL has empty revoked certificates list")]
    EmptyRevokedCertificates,

    /// CRL is missing the mandatory Authority Key Identifier extension.
    #[error("CRL is missing mandatory Authority Key Identifier extension")]
    MissingAuthorityKeyIdentifier,

    /// CRL Authority Key Identifier does not match the signing certificate's Subject Key Identifier.
    #[error("CRL Authority Key Identifier does not match signing certificate's Subject Key Identifier")]
    AuthorityKeyIdentifierMismatch,

    /// CRL is missing the mandatory CRL Number extension.
    #[error("CRL is missing mandatory CRL Number extension")]
    MissingCrlNumber,
}
