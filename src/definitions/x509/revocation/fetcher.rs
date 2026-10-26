//! Revocation fetcher trait and CRL implementations.
//!
//! This module provides:
//! - [`RevocationFetcher`]: Trait for fetching revocation data (CRLs and Status List
//!   Tokens, and in the future OCSP)
//! - [`SimpleRevocationFetcher`]: Basic implementation that wraps an [`HttpClient`]
//! - [`CachingRevocationFetcher`]: Caching implementation with stale-while-revalidate (requires `reqwest` feature)
//!
//! # Architecture
//!
//! The separation of [`HttpClient`] and [`RevocationFetcher`] allows:
//! - Platform-specific HTTP implementations (Rust, Kotlin, Swift) stay simple
//! - CRL parsing, caching, and expiry logic is shared in Rust
//!
//! For cross-platform mobile apps, only [`HttpClient`] needs platform-specific
//! implementation; [`CachingRevocationFetcher`] handles all CRL-specific logic.

use std::sync::Arc;

use async_trait::async_trait;
use der::Decode;
use x509_cert::crl::CertificateList;

use super::{
    error::CrlError,
    http::{HttpClient, HttpMethod, HttpRequest},
};
use crate::definitions::status_list::{StatusListError, STATUS_LIST_CWT_TYPE};

/// Trait for fetching certificate revocation data.
///
/// This trait abstracts revocation data fetching, allowing implementations to add
/// caching, retries, or other middleware behavior. Currently supports CRL fetching,
/// with OCSP support planned for the future.
///
/// For full revocation checking (including signature validation), use
/// [`check_certificate_revocation`](super::check_certificate_revocation).
// TODO: Remove async_trait once edition is upgraded and signature crate
// releases async support without async_trait dependency
#[async_trait]
pub trait RevocationFetcher: Send + Sync {
    /// Fetch and parse a CRL from a URL.
    ///
    /// This method fetches the CRL and parses it, but does not validate the
    /// signature. Use [`check_certificate_revocation`](super::check_certificate_revocation)
    /// for full validation.
    async fn fetch_crl(&self, url: &str) -> Result<CertificateList, CrlError>;

    /// Fetch the Status List Token at the `uri` of an MSO `status_list`.
    ///
    /// This method does not verify the token. The reader verifies it on each use, so a
    /// cache does not depend on the trust point of one MSO. `Arc`, so a cache hit gives a
    /// reference count increment, not a copy.
    ///
    /// The default returns [`StatusListError::NotSupported`]: each MSO with a
    /// `status_list` then gets a warning, so "not checked" never reads as "not revoked".
    async fn fetch_status_list_token(&self, _uri: &str) -> Result<Arc<[u8]>, StatusListError> {
        Err(StatusListError::NotSupported)
    }
}

/// Simple CRL fetcher that wraps an HTTP client without caching.
///
/// This is useful for:
/// - Testing
/// - Short-lived processes where caching isn't beneficial
/// - When you want to implement caching at a different layer
pub struct SimpleRevocationFetcher<C> {
    http_client: C,
}

impl<C: HttpClient> SimpleRevocationFetcher<C> {
    /// Create a new simple CRL fetcher wrapping the given HTTP client.
    pub fn new(http_client: C) -> Self {
        Self { http_client }
    }
}

#[async_trait]
impl<C: HttpClient> RevocationFetcher for SimpleRevocationFetcher<C> {
    async fn fetch_crl(&self, url: &str) -> Result<CertificateList, CrlError> {
        let request = HttpRequest {
            url: url.to_string(),
            method: HttpMethod::Get,
            headers: Vec::new(),
        };

        let response = self
            .http_client
            .request(request)
            .await
            .map_err(|e| CrlError::Fetch {
                url: url.to_string(),
                source: Box::new(e),
            })?;

        if response.status != 200 {
            return Err(CrlError::Fetch {
                url: url.to_string(),
                source: format!("HTTP status {}", response.status).into(),
            });
        }

        CertificateList::from_der(&response.body).map_err(CrlError::Parse)
    }

    async fn fetch_status_list_token(&self, uri: &str) -> Result<Arc<[u8]>, StatusListError> {
        fetch_status_list_token(&self.http_client, uri)
            .await
            .map(Arc::from)
    }
}

async fn fetch_status_list_token<C: HttpClient>(
    http_client: &C,
    uri: &str,
) -> Result<Vec<u8>, StatusListError> {
    let fetch_error = |detail: String| StatusListError::Fetch {
        uri: uri.to_string(),
        detail,
    };

    let response = http_client
        .request(HttpRequest {
            url: uri.to_string(),
            method: HttpMethod::Get,
            // draft-10 8.1. A server can serve the JWT and the CWT form at one URI.
            headers: vec![("Accept".into(), STATUS_LIST_CWT_TYPE.into())],
        })
        .await
        .map_err(|e| fetch_error(e.to_string()))?;

    // draft-10 8.1: a successful response uses a status code in the 2xx range.
    if !(200..300).contains(&response.status) {
        return Err(fetch_error(format!("HTTP status {}", response.status)));
    }

    Ok(response.body)
}

// --- Feature-gated caching implementation ---
#[cfg(feature = "reqwest")]
mod caching {
    use std::{sync::Arc, time::Duration};

    use async_trait::async_trait;
    use der::Decode;
    use moka::future::Cache;
    use time::OffsetDateTime;
    use tracing::{debug, error, warn};
    use x509_cert::crl::CertificateList;

    use super::{fetch_status_list_token, RevocationFetcher};
    use crate::definitions::{
        status_list::{decode_token, StatusListError},
        x509::revocation::{
            error::CrlError,
            http::{HttpClient, HttpMethod, HttpRequest},
        },
    };

    /// Cached CRL entry.
    struct CachedCrl {
        /// The parsed CRL.
        crl: CertificateList,
        /// When this entry was fetched.
        fetched_at: std::time::Instant,
    }

    /// Cached Status List Token.
    #[derive(Clone)]
    struct CachedToken {
        bytes: Arc<[u8]>,
        /// A fresh copy is fetched after this time.
        fresh_until: OffsetDateTime,
        /// The `exp` of the token. After it, the token is never served.
        exp: OffsetDateTime,
    }

    /// CRL fetcher with caching based on CRL's `nextUpdate` field.
    ///
    /// This implementation provides:
    /// - Caching based on CRL's `nextUpdate` validity period
    /// - Stale-while-revalidate: if refetch fails after expiry, continues using
    ///   the stale CRL for a configurable duration (better than no revocation checking)
    /// - Configurable cache capacity and staleness duration
    ///
    /// # Architecture Note
    ///
    /// All CRL-specific logic (parsing, expiry checking) is in this struct, not
    /// in the HTTP client. This means platform-specific HTTP clients (for mobile
    /// platforms like iOS/Android) only need to implement simple HTTP fetching;
    /// the caching and CRL logic can be shared.
    ///
    /// # Resilience
    ///
    /// This fetcher does not implement retries. Resilience is provided by:
    /// - Multiple CRL distribution points: each URL is tried in sequence
    /// - Stale-while-revalidate: cached CRLs can be used if refetch fails
    /// - Non-fatal errors: CRL failures go to `revocation_errors`, not blocking validation
    ///
    /// If more aggressive retry behavior is needed, implement a wrapper that adds
    /// retry logic (e.g., using exponential backoff with jitter).
    ///
    /// # Status List Tokens
    ///
    /// Tokens have their own cache, by `uri`:
    /// - A token is fresh for `ttl` seconds (draft-10 `ttl` claim), limited by
    ///   `status_list_max_ttl` and by its `exp`. A token without `ttl` is fresh for
    ///   `status_list_max_ttl` (default 1 hour).
    /// - After that, the next call fetches again. If that fetch fails, the cached token is
    ///   served until its `exp`: `ttl` says a fresh copy SHOULD be fetched, not that the
    ///   old one is invalid.
    /// - A response that does not decode is an error, like a failed fetch, and is not
    ///   cached.
    ///
    /// The `ttl` and `exp` come from a token that is not verified yet. A forged token can
    /// stay in the cache for at most `status_list_max_ttl`, and it fails verification on
    /// each use.
    // TODO: Consider adding configurable retries if real-world usage shows it's needed.
    // If implemented: only retry transient errors (5xx, timeouts), use exponential
    // backoff with jitter, and make retry count/backoff configurable.
    #[derive(Clone)]
    pub struct CachingRevocationFetcher<C> {
        http_client: C,
        cache: Cache<String, Arc<CachedCrl>>,
        /// How long to continue using a stale CRL if refetch fails.
        max_stale_duration: Duration,
        tokens: Cache<String, CachedToken>,
        status_list_max_ttl: Duration,
    }

    impl<C: HttpClient> CachingRevocationFetcher<C> {
        /// Create a new caching CRL fetcher with default settings.
        ///
        /// Default cache capacity: 100 entries
        /// Default max stale duration: 1 hour
        pub fn new(http_client: C) -> Self {
            Self::with_config(http_client, 100, Duration::from_secs(3600))
        }

        /// Create a new caching CRL fetcher with custom configuration.
        ///
        /// # Arguments
        /// * `http_client` - The underlying HTTP client for fetching CRLs
        /// * `cache_capacity` - Maximum number of CRL entries to cache
        /// * `max_stale` - How long to use a stale CRL if refetch fails
        pub fn with_config(http_client: C, cache_capacity: u64, max_stale: Duration) -> Self {
            let cache = Cache::builder()
                .max_capacity(cache_capacity)
                .time_to_live(Duration::from_secs(86400)) // Max TTL of 24 hours
                .build();

            Self {
                http_client,
                cache,
                max_stale_duration: max_stale,
                tokens: Cache::new(cache_capacity),
                status_list_max_ttl: Duration::from_secs(3600),
            }
        }

        /// Limit how long a Status List Token is fresh, whatever its `ttl`.
        pub fn with_status_list_max_ttl(mut self, max_ttl: Duration) -> Self {
            self.status_list_max_ttl = max_ttl;
            self
        }

        /// Check if a cached CRL is still valid based on its nextUpdate field.
        fn is_crl_valid(cached: &CachedCrl) -> bool {
            let Some(next_update) = &cached.crl.tbs_cert_list.next_update else {
                return true; // No nextUpdate means always valid per RFC 5280
            };

            std::time::SystemTime::now() < next_update.to_system_time()
        }

        /// Check if a stale CRL can still be used (within max_stale_duration).
        fn can_use_stale(&self, cached: &CachedCrl) -> bool {
            cached.fetched_at.elapsed() < self.max_stale_duration
        }

        async fn fetch_and_parse(&self, url: &str) -> Result<CertificateList, CrlError> {
            let request = HttpRequest {
                url: url.to_string(),
                method: HttpMethod::Get,
                headers: Vec::new(),
            };

            let response =
                self.http_client
                    .request(request)
                    .await
                    .map_err(|e| CrlError::Fetch {
                        url: url.to_string(),
                        source: Box::new(e),
                    })?;

            if response.status != 200 {
                return Err(CrlError::Fetch {
                    url: url.to_string(),
                    source: format!("HTTP status {}", response.status).into(),
                });
            }

            CertificateList::from_der(&response.body).map_err(CrlError::Parse)
        }

        async fn fetch_and_cache_token(&self, uri: &str) -> Result<Arc<[u8]>, StatusListError> {
            let bytes: Arc<[u8]> = fetch_status_list_token(&self.http_client, uri)
                .await?
                .into();

            let token = decode_token(&bytes)?;
            let ttl = token.ttl.map_or(self.status_list_max_ttl, |ttl| {
                Duration::from_secs(ttl).min(self.status_list_max_ttl)
            });
            let fresh_until = (OffsetDateTime::now_utc() + ttl).min(token.exp);
            self.tokens
                .insert(
                    uri.to_string(),
                    CachedToken {
                        bytes: bytes.clone(),
                        fresh_until,
                        exp: token.exp,
                    },
                )
                .await;

            Ok(bytes)
        }
    }

    #[async_trait]
    impl<C: HttpClient> RevocationFetcher for CachingRevocationFetcher<C> {
        async fn fetch_crl(&self, url: &str) -> Result<CertificateList, CrlError> {
            // Check cache first
            if let Some(cached) = self.cache.get(url).await {
                if Self::is_crl_valid(&cached) {
                    debug!("CRL cache hit for {url}");
                    return Ok(cached.crl.clone());
                }

                // CRL is stale, try to refetch
                debug!("CRL cache stale for {url}, attempting refetch");
                match self.fetch_and_parse(url).await {
                    Ok(crl) => {
                        let entry = Arc::new(CachedCrl {
                            crl: crl.clone(),
                            fetched_at: std::time::Instant::now(),
                        });
                        self.cache.insert(url.to_string(), entry).await;
                        return Ok(crl);
                    }
                    Err(e) => {
                        // Refetch failed, check if we can use stale
                        if self.can_use_stale(&cached) {
                            warn!("CRL refetch failed for {url}, using stale CRL: {e}");
                            return Ok(cached.crl.clone());
                        }
                        error!("CRL refetch failed and stale CRL too old for {url}: {e}");
                        return Err(e);
                    }
                }
            }

            // No cache entry, fetch fresh
            debug!("CRL cache miss for {url}");
            let crl = self.fetch_and_parse(url).await?;

            let entry = Arc::new(CachedCrl {
                crl: crl.clone(),
                fetched_at: std::time::Instant::now(),
            });
            self.cache.insert(url.to_string(), entry).await;

            Ok(crl)
        }

        async fn fetch_status_list_token(&self, uri: &str) -> Result<Arc<[u8]>, StatusListError> {
            let Some(cached) = self.tokens.get(uri).await else {
                debug!("status list cache miss for {uri}");
                return self.fetch_and_cache_token(uri).await;
            };

            let now = OffsetDateTime::now_utc();
            if now < cached.fresh_until {
                debug!("status list cache hit for {uri}");
                return Ok(cached.bytes);
            }

            match self.fetch_and_cache_token(uri).await {
                Ok(bytes) => Ok(bytes),
                Err(e) if now < cached.exp => {
                    warn!("status list refetch failed for {uri}, using the cached token: {e}");
                    Ok(cached.bytes)
                }
                Err(e) => {
                    self.tokens.invalidate(uri).await;
                    Err(e)
                }
            }
        }
    }
}

#[cfg(feature = "reqwest")]
pub use caching::CachingRevocationFetcher;

/// Implementation of [`RevocationFetcher`] for `()` that always returns an error.
///
/// This allows using `()` as the revocation fetcher type parameter when revocation
/// checking should be skipped. The validation logic will add a warning to
/// revocation_errors when fetch fails, and an MSO status warning for each MSO with a
/// `status_list`.
#[async_trait]
impl RevocationFetcher for () {
    async fn fetch_crl(&self, url: &str) -> Result<CertificateList, CrlError> {
        Err(CrlError::Fetch {
            url: url.to_string(),
            source: "CRL checking is disabled (no CRL fetcher configured)".into(),
        })
    }
}
