//! HTTP client trait for fetching CRLs (and future OCSP support).

use async_trait::async_trait;

/// HTTP request to be sent by an HTTP client.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The URL to send the request to.
    pub url: String,
    /// The HTTP method and optional body.
    pub method: HttpMethod,
}

/// HTTP method with optional body for POST requests.
#[derive(Debug, Clone)]
pub enum HttpMethod {
    /// HTTP GET request.
    Get,
    /// HTTP POST request with body and content type.
    Post { body: Vec<u8>, content_type: String },
}

/// HTTP response from an HTTP client.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: Vec<u8>,
}
// NOTE: We intentionally don't include response headers or validate Content-Type.
// RFC 2585 specifies `application/pkix-crl` for CRLs and RFC 6960 specifies
// `application/ocsp-response` for OCSP, but in practice many servers return
// incorrect types (application/octet-stream, text/plain, etc.). Since the data
// is DER-encoded, invalid responses will fail to parse anyway.

/// Low-level HTTP client trait.
///
/// This trait provides a pure HTTP interface with no knowledge of CRL semantics.
/// Implementors only need to provide the [`request`](Self::request) method.
///
/// For CRL fetching with caching, wrap this in a [`RevocationFetcher`](super::RevocationFetcher) implementation.
/// For full revocation checking, use [`check_certificate_revocation`](super::check_certificate_revocation).
// TODO: Remove async_trait once edition is upgraded and signature crate
// releases async support without async_trait dependency
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// The error type returned by this HTTP client.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Send an HTTP request and return the response.
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error>;
}

/// Error returned when using `()` as an HTTP client (CRL checking disabled).
#[derive(Debug, thiserror::Error)]
#[error("CRL checking is disabled (no HTTP client configured)")]
pub struct NoHttpClientError;

/// Implementation of [`HttpClient`] for `()` that always returns an error.
///
/// This allows using `()` as the HTTP client type parameter when CRL checking
/// should be skipped. The validation logic will add a warning to revocation_errors
/// when fetch fails.
#[async_trait]
impl HttpClient for () {
    type Error = NoHttpClientError;

    async fn request(&self, _request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        Err(NoHttpClientError)
    }
}
