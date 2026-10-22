//! Fetchers for Status List Tokens.
//!
//! - [`StatusListFetcher`]: the trait the reader calls with the `uri` of the MSO status.
//! - [`SimpleStatusListFetcher`]: one HTTP GET for each call, no cache.
//! - [`CachingStatusListFetcher`]: a cache that follows the `ttl` and `exp` of each token
//!   (requires the `reqwest` feature).
//!
//! A fetcher does not verify the token. The reader verifies it on each use, so a cache does
//! not depend on the trust point of one MSO.

use std::sync::Arc;

use async_trait::async_trait;

use super::{StatusListError, STATUS_LIST_CWT_TYPE};
use crate::definitions::x509::revocation::{HttpClient, HttpMethod, HttpRequest};

/// Fetches the Status List Token at the `uri` of an MSO `status_list`.
///
/// Separate from [`RevocationFetcher`](crate::definitions::x509::revocation::RevocationFetcher):
/// a CRL cache follows `nextUpdate`, a status list cache follows `ttl` and `exp`.
// TODO: Remove async_trait once edition is upgraded and signature crate
// releases async support without async_trait dependency
#[async_trait]
pub trait StatusListFetcher: Send + Sync {
    /// The raw token. `Arc`, so a cache hit gives a reference count increment, not a copy.
    async fn fetch_status_list_token(&self, uri: &str) -> Result<Arc<[u8]>, StatusListError>;
}

/// A fetcher with no cache: one HTTP GET for each call.
pub struct SimpleStatusListFetcher<C> {
    http_client: C,
}

impl<C: HttpClient> SimpleStatusListFetcher<C> {
    pub fn new(http_client: C) -> Self {
        Self { http_client }
    }
}

#[async_trait]
impl<C: HttpClient> StatusListFetcher for SimpleStatusListFetcher<C> {
    async fn fetch_status_list_token(&self, uri: &str) -> Result<Arc<[u8]>, StatusListError> {
        fetch(&self.http_client, uri).await.map(Arc::from)
    }
}

async fn fetch<C: HttpClient>(http_client: &C, uri: &str) -> Result<Vec<u8>, StatusListError> {
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

    if response.status != 200 {
        return Err(fetch_error(format!("HTTP status {}", response.status)));
    }

    Ok(response.body)
}

#[cfg(feature = "reqwest")]
mod caching {
    use std::{sync::Arc, time::Duration};

    use async_trait::async_trait;
    use moka::future::Cache;
    use time::OffsetDateTime;
    use tracing::{debug, warn};

    use super::{fetch, StatusListFetcher};
    use crate::definitions::{
        status_list::{decode_token, StatusListError},
        x509::revocation::HttpClient,
    };

    #[derive(Clone)]
    struct CachedToken {
        bytes: Arc<[u8]>,
        /// A fresh copy is fetched after this time.
        fresh_until: OffsetDateTime,
        /// The `exp` of the token. After it, the token is never served.
        exp: OffsetDateTime,
    }

    /// A fetcher that caches each token by `uri`.
    ///
    /// - A token is fresh for `ttl` seconds (draft-10 `ttl` claim), limited by `max_ttl`
    ///   and by its `exp`. A token without `ttl` is fresh for `max_ttl`.
    /// - After that, the next call fetches again. If that fetch fails, the cached token is
    ///   served until its `exp`: `ttl` says a fresh copy SHOULD be fetched, not that the
    ///   old one is invalid.
    /// - A response that does not decode is an error, like a failed fetch, and is not
    ///   cached.
    ///
    /// The `ttl` and `exp` come from a token that is not verified yet. A forged token can
    /// stay in the cache for at most `max_ttl`, and it fails verification on each use.
    #[derive(Clone)]
    pub struct CachingStatusListFetcher<C> {
        http_client: C,
        cache: Cache<String, CachedToken>,
        max_ttl: Duration,
    }

    impl<C: HttpClient> CachingStatusListFetcher<C> {
        /// 100 entries, `max_ttl` of 1 hour.
        pub fn new(http_client: C) -> Self {
            Self::with_config(http_client, 100, Duration::from_secs(3600))
        }

        pub fn with_config(http_client: C, cache_capacity: u64, max_ttl: Duration) -> Self {
            Self {
                http_client,
                cache: Cache::new(cache_capacity),
                max_ttl,
            }
        }

        async fn fetch_and_cache(&self, uri: &str) -> Result<Arc<[u8]>, StatusListError> {
            let bytes: Arc<[u8]> = fetch(&self.http_client, uri).await?.into();

            let token = decode_token(&bytes)?;
            let ttl = token.ttl.map_or(self.max_ttl, |ttl| {
                Duration::from_secs(ttl).min(self.max_ttl)
            });
            let fresh_until = (OffsetDateTime::now_utc() + ttl).min(token.exp);
            self.cache
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
    impl<C: HttpClient> StatusListFetcher for CachingStatusListFetcher<C> {
        async fn fetch_status_list_token(&self, uri: &str) -> Result<Arc<[u8]>, StatusListError> {
            let Some(cached) = self.cache.get(uri).await else {
                debug!("status list cache miss for {uri}");
                return self.fetch_and_cache(uri).await;
            };

            let now = OffsetDateTime::now_utc();
            if now < cached.fresh_until {
                debug!("status list cache hit for {uri}");
                return Ok(cached.bytes);
            }

            match self.fetch_and_cache(uri).await {
                Ok(bytes) => Ok(bytes),
                Err(e) if now < cached.exp => {
                    warn!("status list refetch failed for {uri}, using the cached token: {e}");
                    Ok(cached.bytes)
                }
                Err(e) => {
                    self.cache.invalidate(uri).await;
                    Err(e)
                }
            }
        }
    }
}

#[cfg(feature = "reqwest")]
pub use caching::CachingStatusListFetcher;

/// For a reader that does not check the MSO status. Each MSO with a `status_list` then gets
/// a warning, so "not checked" never reads as "not revoked".
#[async_trait]
impl StatusListFetcher for () {
    async fn fetch_status_list_token(&self, _uri: &str) -> Result<Arc<[u8]>, StatusListError> {
        Err(StatusListError::NotSupported)
    }
}
