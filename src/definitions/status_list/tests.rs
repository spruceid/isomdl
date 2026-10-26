use super::{
    compressed_status_at, decode_token, status_at, verify_token, StatusListError, StatusListToken,
    STATUS_LIST_CWT_TYPE,
};
use crate::definitions::x509::{
    test::TestPki, validation::ValidationOptions, x5chain::X5CHAIN_COSE_HEADER_LABEL, X5Chain,
};
use ciborium::Value;
use coset::{
    iana, CborSerializable, CoseSign1Builder, HeaderBuilder, Label, TaggedCborSerializable,
};
use flate2::bufread::ZlibDecoder;
use serde::Deserialize;
use signature::Signer;
use std::collections::BTreeMap;
use std::io::Read;
use time::OffsetDateTime;

// Claim values from ISO/IEC 18013-5 CD Annex D.6.
const SUB: &str = "https://example.com/statuslists/1";
const IAT: i64 = 1686920170;
const EXP: i64 = 2291720170;
const TTL: u64 = 43200;

fn int(i: i64) -> Value {
    Value::Integer(i.into())
}

fn status_list_claim(bits: i64, lst: Vec<u8>) -> Value {
    Value::Map(vec![
        (Value::Text("bits".into()), int(bits)),
        (Value::Text("lst".into()), Value::Bytes(lst)),
    ])
}

/// The claims of a valid token. Each test changes the claim it is about.
fn claims() -> Vec<(i64, Value)> {
    vec![
        (2, Value::Text(SUB.into())),
        (6, int(IAT)),
        (4, int(EXP)),
        (65534, int(TTL as i64)),
        (
            65533,
            status_list_claim(1, hex::decode(COMPRESSED_LST_1).unwrap()),
        ),
    ]
}

fn without(key: i64) -> Vec<(i64, Value)> {
    claims().into_iter().filter(|(k, _)| *k != key).collect()
}

/// A token with a dummy signature: `decode_token` does not verify it.
fn token(typ: Option<&str>, claims: Vec<(i64, Value)>, tagged: bool) -> Vec<u8> {
    let mut protected = HeaderBuilder::new().algorithm(iana::Algorithm::ES256);
    if let Some(typ) = typ {
        protected = protected.value(16, Value::Text(typ.into()));
    }
    let payload = Value::Map(claims.into_iter().map(|(k, v)| (int(k), v)).collect());
    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected.build())
        .payload(crate::cbor::to_vec(&payload).unwrap())
        .signature(vec![0; 64])
        .build();
    if tagged {
        cose_sign1.to_tagged_vec().unwrap()
    } else {
        cose_sign1.to_vec().unwrap()
    }
}

#[test]
fn decodes_a_token() {
    for tagged in [true, false] {
        let decoded = decode_token(&token(Some(STATUS_LIST_CWT_TYPE), claims(), tagged)).unwrap();
        assert_eq!(decoded.sub, SUB);
        assert_eq!(
            decoded.iat,
            OffsetDateTime::from_unix_timestamp(IAT).unwrap()
        );
        assert_eq!(
            decoded.exp,
            OffsetDateTime::from_unix_timestamp(EXP).unwrap()
        );
        assert_eq!(decoded.ttl, Some(TTL));
        assert_eq!(decoded.bits, 1);
        assert_eq!(
            compressed_status_at(&decoded.lst, decoded.bits, 0),
            Ok(STATUSES_1[0])
        );
    }
}

#[test]
fn decodes_a_token_without_ttl() {
    let decoded = decode_token(&token(Some(STATUS_LIST_CWT_TYPE), without(65534), true)).unwrap();
    assert_eq!(decoded.ttl, None);
}

#[test]
fn ignores_unknown_claims_and_unknown_status_list_keys() {
    let mut claims = without(65533);
    claims.push((1, Value::Text("https://example.com".into())));
    claims.push((
        65533,
        Value::Map(vec![
            (Value::Text("bits".into()), int(1)),
            (Value::Text("lst".into()), Value::Bytes(vec![0x78, 0xda])),
            (
                Value::Text("aggregation_uri".into()),
                Value::Text("https://example.com/statuslists/aggregation".into()),
            ),
        ]),
    ));
    assert!(decode_token(&token(Some(STATUS_LIST_CWT_TYPE), claims, true)).is_ok());
}

#[test]
fn refuses_a_token_without_the_status_list_type() {
    // `statuslist+cwt` is the short form that ISO/IEC 18013-5 CD Annex D.6 uses.
    for typ in [
        None,
        Some("statuslist+cwt"),
        Some("application/identifierlist+cwt"),
    ] {
        assert_eq!(
            decode_token(&token(typ, claims(), true)).unwrap_err(),
            StatusListError::WrongType,
            "typ {typ:?}"
        );
    }
}

#[test]
fn refuses_a_token_without_a_required_claim() {
    for (key, name) in [(2, "sub"), (6, "iat"), (4, "exp"), (65533, "status_list")] {
        assert_eq!(
            decode_token(&token(Some(STATUS_LIST_CWT_TYPE), without(key), true)).unwrap_err(),
            StatusListError::MissingClaim(name)
        );
    }
}

#[test]
fn refuses_a_malformed_claim() {
    let mut claims = without(4);
    claims.push((4, Value::Text("tomorrow".into())));
    assert_eq!(
        decode_token(&token(Some(STATUS_LIST_CWT_TYPE), claims, true)).unwrap_err(),
        StatusListError::MalformedClaim("exp")
    );

    let mut claims = without(65533);
    claims.push((65533, status_list_claim(-1, vec![])));
    assert_eq!(
        decode_token(&token(Some(STATUS_LIST_CWT_TYPE), claims, true)).unwrap_err(),
        StatusListError::MalformedClaim("bits")
    );
}

#[test]
fn refuses_bytes_that_are_not_a_cose_sign1() {
    assert!(matches!(
        decode_token(&[0xa0]),
        Err(StatusListError::MalformedToken(_))
    ));
}

/// The protected header of a valid token, with `x5chain`.
fn protected(x5chain: &X5Chain) -> HeaderBuilder {
    HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .value(16, Value::Text(STATUS_LIST_CWT_TYPE.into()))
        .value(X5CHAIN_COSE_HEADER_LABEL, x5chain.into_cbor())
}

fn signed(
    protected: HeaderBuilder,
    claims: Vec<(i64, Value)>,
    key: &p256::ecdsa::SigningKey,
) -> StatusListToken {
    let payload = Value::Map(claims.into_iter().map(|(k, v)| (int(k), v)).collect());
    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected.build())
        .payload(crate::cbor::to_vec(&payload).unwrap())
        .create_signature(&[], |data| {
            let signature: p256::ecdsa::Signature = key.sign(data);
            signature.to_bytes().to_vec()
        })
        .build();
    decode_token(&cose_sign1.to_tagged_vec().unwrap()).unwrap()
}

async fn verify(
    token: &StatusListToken,
    trust_point: &TestPki,
) -> Result<Vec<String>, StatusListError> {
    verify_token(
        token,
        SUB,
        &trust_point.root,
        &trust_point.fetcher(),
        &ValidationOptions::default(),
    )
    .await
}

#[tokio::test]
async fn verifies_a_token_signed_under_the_trust_point() {
    let pki = TestPki::issuer();
    let token = signed(protected(&pki.x5chain()), claims(), &pki.leaf_key);
    assert_eq!(verify(&token, &pki).await, Ok(vec![]));
}

/// 12.3.6.2 allows the trust point at the top of `x5chain`, not only as its signer.
#[tokio::test]
async fn verifies_a_token_whose_x5chain_holds_the_trust_point() {
    let pki = TestPki::issuer();
    let x5chain = X5Chain::builder()
        .with_certificate(pki.leaf.clone())
        .unwrap()
        .with_certificate(pki.root.clone())
        .unwrap()
        .build()
        .unwrap();
    let protected = protected(&x5chain);
    let token = signed(protected, claims(), &pki.leaf_key);
    assert_eq!(verify(&token, &pki).await, Ok(vec![]));
}

/// The reader trusts both IACAs for documents, but only the one of this MSO for its list.
#[tokio::test]
async fn refuses_a_token_signed_under_another_trust_point() {
    let pki = TestPki::issuer();
    let token = signed(protected(&pki.x5chain()), claims(), &pki.leaf_key);
    assert!(matches!(
        verify(&token, &TestPki::issuer()).await,
        Err(StatusListError::UntrustedSigner(_))
    ));
}

#[tokio::test]
async fn refuses_a_token_signed_by_a_revoked_certificate() {
    let pki = TestPki::issuer();
    let token = signed(protected(&pki.x5chain()), claims(), &pki.leaf_key);
    let result = verify_token(
        &token,
        SUB,
        &pki.root,
        &pki.fetcher_revoking(&[pki.leaf_serial()]),
        &ValidationOptions::default(),
    )
    .await;
    assert!(matches!(result, Err(StatusListError::UntrustedSigner(_))));
}

#[tokio::test]
async fn returns_a_crl_failure_as_a_warning() {
    let pki = TestPki::issuer();
    let token = signed(protected(&pki.x5chain()), claims(), &pki.leaf_key);
    let warnings = verify_token(&token, SUB, &pki.root, &(), &ValidationOptions::default())
        .await
        .unwrap();
    assert!(!warnings.is_empty());
}

#[tokio::test]
async fn refuses_a_token_with_the_x5chain_in_the_unprotected_header() {
    let pki = TestPki::issuer();
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .value(16, Value::Text(STATUS_LIST_CWT_TYPE.into()));
    let mut token = signed(protected, claims(), &pki.leaf_key);
    // The unprotected header is not signed, so this needs no new signature.
    token.cose_sign1.unprotected.rest.push((
        Label::Int(X5CHAIN_COSE_HEADER_LABEL),
        pki.x5chain().into_cbor(),
    ));
    assert_eq!(
        verify(&token, &pki).await,
        Err(StatusListError::MissingX5Chain)
    );
}

#[tokio::test]
async fn refuses_a_token_signed_by_another_key() {
    let pki = TestPki::issuer();
    let token = signed(
        protected(&pki.x5chain()),
        claims(),
        &TestPki::issuer().leaf_key,
    );
    assert!(matches!(
        verify(&token, &pki).await,
        Err(StatusListError::Signature(_))
    ));
}

#[tokio::test]
async fn refuses_a_token_without_alg() {
    let pki = TestPki::issuer();
    let protected = HeaderBuilder::new()
        .value(16, Value::Text(STATUS_LIST_CWT_TYPE.into()))
        .value(X5CHAIN_COSE_HEADER_LABEL, pki.x5chain().into_cbor());
    let token = signed(protected, claims(), &pki.leaf_key);
    assert!(matches!(
        verify(&token, &pki).await,
        Err(StatusListError::Signature(_))
    ));
}

#[tokio::test]
async fn refuses_an_alg_that_does_not_match_the_key() {
    let pki = TestPki::issuer();
    let protected = protected(&pki.x5chain()).algorithm(iana::Algorithm::ES384);
    let token = signed(protected, claims(), &pki.leaf_key);
    assert!(matches!(
        verify(&token, &pki).await,
        Err(StatusListError::Signature(_))
    ));
}

#[tokio::test]
async fn refuses_a_token_for_another_uri() {
    let pki = TestPki::issuer();
    let token = signed(protected(&pki.x5chain()), claims(), &pki.leaf_key);
    let result = verify_token(
        &token,
        "https://example.com/statuslists/2",
        &pki.root,
        &pki.fetcher(),
        &ValidationOptions::default(),
    )
    .await;
    assert_eq!(
        result,
        Err(StatusListError::SubjectMismatch {
            expected: "https://example.com/statuslists/2".into(),
            found: SUB.into(),
        })
    );
}

#[tokio::test]
async fn refuses_an_expired_token() {
    let pki = TestPki::issuer();
    let exp = OffsetDateTime::now_utc().unix_timestamp() - 1;
    let mut claims = without(4);
    claims.push((4, int(exp)));
    let token = signed(protected(&pki.x5chain()), claims, &pki.leaf_key);
    assert_eq!(
        verify(&token, &pki).await,
        Err(StatusListError::Expired(
            OffsetDateTime::from_unix_timestamp(exp).unwrap()
        ))
    );
}

/// draft-ietf-oauth-status-list-10 Appendix C: four lists of 2^20 entries, with `bits` of
/// 1, 2, 4 and 8. Entries not in `statuses` are 0 (VALID).
static APPENDIX_C: &str =
    include_str!("../../../test/definitions/status_list/draft-10-test-vectors.json");
const APPENDIX_C_SIZE: u64 = 1 << 20;

#[derive(Deserialize)]
struct Vector {
    bits: u8,
    /// Hex of the compressed `lst`, taken from the CBOR encoding of each example.
    lst: String,
    statuses: BTreeMap<u64, u8>,
}

fn appendix_c() -> Vec<Vector> {
    serde_json::from_str(APPENDIX_C).unwrap()
}

#[test]
fn reads_every_entry_of_the_appendix_c_lists() {
    for vector in appendix_c() {
        let mut lst = Vec::new();
        ZlibDecoder::new(hex::decode(&vector.lst).unwrap().as_slice())
            .read_to_end(&mut lst)
            .unwrap();
        assert_eq!(
            lst.len() as u64,
            APPENDIX_C_SIZE * u64::from(vector.bits) / 8
        );

        for idx in 0..APPENDIX_C_SIZE {
            let expected = vector.statuses.get(&idx).copied().unwrap_or(0);
            assert_eq!(
                status_at(&lst, vector.bits, idx),
                Ok(expected),
                "bits {}, idx {idx}",
                vector.bits
            );
        }
        assert_eq!(
            status_at(&lst, vector.bits, APPENDIX_C_SIZE),
            Err(StatusListError::IndexOutOfRange(APPENDIX_C_SIZE))
        );
    }
}

#[test]
fn reads_the_appendix_c_statuses_from_the_compressed_lists() {
    for vector in appendix_c() {
        let lst = hex::decode(&vector.lst).unwrap();
        for (idx, expected) in &vector.statuses {
            assert_eq!(
                compressed_status_at(&lst, vector.bits, *idx),
                Ok(*expected),
                "bits {}, idx {idx}",
                vector.bits
            );
        }
        assert_eq!(
            compressed_status_at(&lst, vector.bits, APPENDIX_C_SIZE),
            Err(StatusListError::IndexOutOfRange(APPENDIX_C_SIZE))
        );
    }
}

// draft-ietf-oauth-status-list-10 4.1, `bits` = 1.
const LST_1: [u8; 2] = [0xb9, 0xa3];
const COMPRESSED_LST_1: &str = "78dadbb918000217015d";
const STATUSES_1: [u8; 16] = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];

// draft-ietf-oauth-status-list-10 4.1, `bits` = 2.
const LST_2: [u8; 3] = [0xc9, 0x44, 0xf9];
const COMPRESSED_LST_2: &str = "78da3be9f2130003df0207";
const STATUSES_2: [u8; 12] = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];

#[test]
fn reads_every_status_of_the_compressed_examples() {
    let lst_1 = hex::decode(COMPRESSED_LST_1).unwrap();
    for (idx, expected) in STATUSES_1.iter().enumerate() {
        assert_eq!(
            compressed_status_at(&lst_1, 1, idx as u64),
            Ok(*expected),
            "idx {idx}"
        );
    }
    let lst_2 = hex::decode(COMPRESSED_LST_2).unwrap();
    for (idx, expected) in STATUSES_2.iter().enumerate() {
        assert_eq!(
            compressed_status_at(&lst_2, 2, idx as u64),
            Ok(*expected),
            "idx {idx}"
        );
    }
}

/// Without the 4-byte Adler-32 trailer the stream is incomplete, but the first byte still
/// decompresses: only the prefix up to `idx` is read.
#[test]
fn reads_a_compressed_status_without_the_zlib_trailer() {
    let lst = hex::decode(COMPRESSED_LST_1).unwrap();
    assert_eq!(
        compressed_status_at(&lst[..lst.len() - 4], 1, 0),
        Ok(STATUSES_1[0])
    );
}

#[test]
fn refuses_an_index_past_the_end_of_a_compressed_list() {
    let lst = hex::decode(COMPRESSED_LST_1).unwrap();
    assert_eq!(
        compressed_status_at(&lst, 1, 16),
        Err(StatusListError::IndexOutOfRange(16))
    );
}

#[test]
fn refuses_a_list_that_is_not_zlib() {
    assert!(matches!(
        compressed_status_at(&LST_1, 1, 0),
        Err(StatusListError::Decompression(_))
    ));
}

#[test]
fn reads_every_status_of_the_one_bit_example() {
    for (idx, expected) in STATUSES_1.iter().enumerate() {
        assert_eq!(status_at(&LST_1, 1, idx as u64), Ok(*expected), "idx {idx}");
    }
}

#[test]
fn reads_every_status_of_the_two_bit_example() {
    for (idx, expected) in STATUSES_2.iter().enumerate() {
        assert_eq!(status_at(&LST_2, 2, idx as u64), Ok(*expected), "idx {idx}");
    }
}

#[test]
fn reads_a_whole_byte_when_bits_is_eight() {
    assert_eq!(status_at(&[0x00, 0x2a], 8, 1), Ok(0x2a));
}

#[test]
fn refuses_an_index_past_the_end() {
    assert_eq!(
        status_at(&LST_1, 1, 16),
        Err(StatusListError::IndexOutOfRange(16))
    );
}

#[test]
fn refuses_an_index_whose_bit_position_overflows() {
    assert_eq!(
        status_at(&LST_1, 8, u64::MAX),
        Err(StatusListError::IndexOutOfRange(u64::MAX))
    );
}

#[test]
fn refuses_a_status_size_the_draft_does_not_allow() {
    for bits in [0, 3, 5, 16] {
        assert_eq!(
            status_at(&LST_1, bits, 0),
            Err(StatusListError::InvalidBits(bits)),
            "bits {bits}"
        );
    }
}

#[cfg(feature = "reqwest")]
mod fetcher {
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use time::OffsetDateTime;
    use wiremock::{
        matchers::{header, method},
        Mock, MockServer, ResponseTemplate,
    };

    use super::{claims, int, token, without, SUB};
    use crate::definitions::{
        status_list::{StatusListError, STATUS_LIST_CWT_TYPE},
        x509::revocation::{
            CachingRevocationFetcher, HttpClient, HttpRequest, HttpResponse, NoHttpClientError,
            ReqwestClient, RevocationFetcher, SimpleRevocationFetcher,
        },
    };

    /// The mock answers only a request that asks for the CWT form, so this also checks
    /// that `ReqwestClient` sends the headers of the request.
    #[tokio::test]
    async fn asks_for_the_cwt_form() {
        let server = MockServer::start().await;
        let body = token(Some(STATUS_LIST_CWT_TYPE), claims(), true);
        Mock::given(method("GET"))
            .and(header("accept", STATUS_LIST_CWT_TYPE))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .expect(1)
            .mount(&server)
            .await;

        let fetched = SimpleRevocationFetcher::new(ReqwestClient::new().unwrap())
            .fetch_status_list_token(&server.uri())
            .await
            .unwrap();
        assert_eq!(*fetched, *body);
    }

    /// Serves `responses` in order, and counts the requests.
    struct Scripted {
        responses: Mutex<VecDeque<Result<HttpResponse, NoHttpClientError>>>,
        requests: AtomicUsize,
    }

    impl Scripted {
        fn new(
            responses: impl IntoIterator<Item = Result<HttpResponse, NoHttpClientError>>,
        ) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: AtomicUsize::new(0),
            }
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl HttpClient for &Scripted {
        type Error = NoHttpClientError;

        async fn request(&self, _request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("no response left")
        }
    }

    fn ok(body: Vec<u8>) -> Result<HttpResponse, NoHttpClientError> {
        Ok(HttpResponse { status: 200, body })
    }

    /// draft-10 8.1: any status code in the 2xx range is a success.
    #[tokio::test]
    async fn accepts_any_2xx_status() {
        let body = token(Some(STATUS_LIST_CWT_TYPE), claims(), true);
        let client = Scripted::new([
            Ok(HttpResponse {
                status: 203,
                body: body.clone(),
            }),
            Ok(HttpResponse {
                status: 300,
                body: body.clone(),
            }),
        ]);
        let fetcher = SimpleRevocationFetcher::new(&client);
        assert_eq!(*fetcher.fetch_status_list_token(SUB).await.unwrap(), *body);
        assert!(matches!(
            fetcher.fetch_status_list_token(SUB).await,
            Err(StatusListError::Fetch { .. })
        ));
    }

    /// A token whose `ttl` claim is `ttl` seconds.
    fn token_with_ttl(ttl: i64) -> Vec<u8> {
        let mut claims = without(65534);
        claims.push((65534, int(ttl)));
        token(Some(STATUS_LIST_CWT_TYPE), claims, true)
    }

    #[tokio::test]
    async fn serves_a_fresh_token_from_the_cache() {
        let body = token_with_ttl(43200);
        let client = Scripted::new([ok(body.clone())]);
        let fetcher = CachingRevocationFetcher::new(&client);
        for _ in 0..2 {
            assert_eq!(*fetcher.fetch_status_list_token(SUB).await.unwrap(), *body);
        }
        assert_eq!(client.requests(), 1);
    }

    #[tokio::test]
    async fn max_ttl_limits_the_ttl_of_the_token() {
        let client = Scripted::new([ok(token_with_ttl(43200)), ok(token_with_ttl(43200))]);
        let fetcher =
            CachingRevocationFetcher::new(&client).with_status_list_max_ttl(Duration::ZERO);
        for _ in 0..2 {
            fetcher.fetch_status_list_token(SUB).await.unwrap();
        }
        assert_eq!(client.requests(), 2);
    }

    /// `ttl` 0: the second call fetches again, and the fetch fails.
    #[tokio::test]
    async fn serves_the_cached_token_when_the_refetch_fails() {
        let body = token_with_ttl(0);
        let client = Scripted::new([ok(body.clone()), Err(NoHttpClientError)]);
        let fetcher = CachingRevocationFetcher::new(&client);
        fetcher.fetch_status_list_token(SUB).await.unwrap();
        assert_eq!(*fetcher.fetch_status_list_token(SUB).await.unwrap(), *body);
        assert_eq!(client.requests(), 2);
    }

    #[tokio::test]
    async fn does_not_serve_a_cached_token_after_its_exp() {
        let mut claims = without(4);
        claims.push((4, int(OffsetDateTime::now_utc().unix_timestamp() - 1)));
        let expired = token(Some(STATUS_LIST_CWT_TYPE), claims, true);
        let client = Scripted::new([ok(expired), Err(NoHttpClientError)]);
        let fetcher = CachingRevocationFetcher::new(&client);
        fetcher.fetch_status_list_token(SUB).await.unwrap();
        assert!(matches!(
            fetcher.fetch_status_list_token(SUB).await,
            Err(StatusListError::Fetch { .. })
        ));
    }

    #[tokio::test]
    async fn does_not_cache_a_response_that_does_not_decode() {
        let client = Scripted::new([ok(vec![0xa0]), ok(token_with_ttl(43200))]);
        let fetcher = CachingRevocationFetcher::new(&client);
        assert!(matches!(
            fetcher.fetch_status_list_token(SUB).await,
            Err(StatusListError::MalformedToken(_))
        ));
        fetcher.fetch_status_list_token(SUB).await.unwrap();
        assert_eq!(client.requests(), 2);
    }
}
