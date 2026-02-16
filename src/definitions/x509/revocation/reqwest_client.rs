//! Reqwest-based HTTP client for revocation checking.
//!
//! This is a simple HTTP client without caching. For CRL-aware caching,
//! wrap this in a [`CachingRevocationFetcher`](super::CachingRevocationFetcher).

use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;

use super::{HttpClient, HttpMethod, HttpRequest, HttpResponse};

/// Simple HTTP client implementation using reqwest.
///
/// This client provides basic HTTP functionality without caching.
/// For CRL-aware caching, wrap this client in [`CachingRevocationFetcher`](super::CachingRevocationFetcher):
///
/// ```ignore
/// use isomdl::definitions::x509::revocation::{CachingRevocationFetcher, ReqwestClient};
///
/// let http_client = ReqwestClient::new()?;
/// let revocation_fetcher = CachingRevocationFetcher::new(http_client);
/// ```
#[derive(Clone)]
pub struct ReqwestClient {
    client: reqwest::Client,
}

impl ReqwestClient {
    /// Create a new ReqwestClient with default settings.
    ///
    /// Default timeout: 30 seconds
    pub fn new() -> anyhow::Result<Self> {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a new ReqwestClient with custom timeout.
    pub fn with_timeout(timeout: Duration) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self { client })
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    type Error = reqwest::Error;

    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let url = &request.url;

        let req_builder = match request.method {
            HttpMethod::Get => self.client.get(url),
            HttpMethod::Post { body, content_type } => self
                .client
                .post(url)
                .header("Content-Type", content_type)
                .body(body),
        };

        let response = req_builder.send().await?;
        let status = response.status().as_u16();
        let body = response.bytes().await?.to_vec();

        Ok(HttpResponse { status, body })
    }
}
