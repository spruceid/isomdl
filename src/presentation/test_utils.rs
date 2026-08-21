//! Shared fixtures for the presentation-layer tests.
//!
//! These cannot live in `tests/`: an integration test links the library *without*
//! `cfg(test)`, so `issue_test_mdoc` and the x509 test PKI are invisible there. Anything
//! that mints a certificate or issues an mdoc has to stay inside `src/`.
#![allow(dead_code)]

use digest::Mac;
use hmac::Hmac;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::Sha256;

use crate::{
    definitions::x509::test::TestPki,
    definitions::{
        device_engagement::Security,
        device_request::{DataElements, ItemsRequest, Namespaces},
        device_request::{DeviceRequest, DocRequest},
        device_response::Document as ResponseDocument,
        device_signed::{DeviceAuth, DeviceAuthType},
        helpers::Tag24,
        issuer_signed::IssuerSignedItemBytes,
        session::{
            create_p256_ephemeral_keys, derive_e_mac_key, derive_session_key, get_shared_secret,
            Handover, SessionTranscript180135,
        },
        x509::x5chain::X5CHAIN_COSE_HEADER_LABEL,
        DeviceEngagement, DeviceResponse, IssuerSignedItem, SessionEstablishment,
    },
    issuance::Mdoc,
    presentation::device::{
        Document, Documents, PermittedItems, PreparedDeviceResponse, RequestedItems,
        SessionManagerEngaged,
    },
    presentation::reader::ReaderAuthentication,
};

use super::device::DeviceSession;

/// What a test asks for: a doc type, a namespace within it, and some elements.
pub(crate) type Ask<'a> = (&'a str, &'a str, &'a [&'a str]);

/// A device session that exists only to produce a [`DeviceResponse`].
///
/// It implements the public [`DeviceSession`] trait, so it drives exactly the same
/// response-building code the real [`SessionManager`](super::device::SessionManager)
/// does — but without session encryption, which the reader-side tests do not care about.
struct TestDeviceSession {
    documents: Documents,
    session_transcript: SessionTranscript180135,
    device_auth_type: DeviceAuthType,
}

impl DeviceSession for TestDeviceSession {
    type ST = SessionTranscript180135;

    fn documents(&self) -> &Documents {
        &self.documents
    }

    fn session_transcript(&self) -> Self::ST {
        self.session_transcript.clone()
    }

    fn device_auth_type(&self) -> DeviceAuthType {
        self.device_auth_type
    }
}

/// Builds plaintext [`DeviceResponse`]s from issued mdocs.
///
/// ## Same doc type twice
///
/// [`Documents`] is a `NonEmptyMap<DocType, Document>`, so `prepare_response` emits **at
/// most one document per doc type** — a fixture with two documents of the same doc type
/// cannot be produced through the device API at all. Build one and clone the finalized
/// [`ResponseDocument`]; see [`TestExchange::duplicate_document`].
pub(crate) struct TestExchange {
    session: TestDeviceSession,
    device_key: SigningKey,
    e_reader_key_private: [u8; 32],
}

impl TestExchange {
    /// The device key baked into every mdoc that
    /// [`issue_test_mdoc`](crate::issuance::mdoc::test::issue_test_mdoc) produces.
    pub(crate) fn device_signing_key() -> SigningKey {
        let der = base64::decode(include_str!("../../test/issuance/device_key.b64").trim())
            .expect("device key fixture is not valid base64");
        p256::SecretKey::from_sec1_der(&der)
            .expect("device key fixture is not a valid SEC1 key")
            .into()
    }

    /// A session holding `mdocs`, keyed by doc type, authenticating with COSE_Sign1.
    ///
    /// If two mdocs share a doc type only the last one survives — [`Documents`] is a map.
    /// See the note on [`TestExchange`] and use [`TestExchange::duplicate_document`].
    pub(crate) fn new(mdocs: impl IntoIterator<Item = Mdoc>) -> Self {
        Self::with_auth_type(mdocs, DeviceAuthType::Sign1)
    }

    /// As [`TestExchange::new`], but the device authenticates with COSE_Mac0.
    ///
    /// The MAC path is not a variation on the signature path: it derives EMacKey from
    /// `ECDH(SDeviceKey, EReaderKey)` (ISO 18013-5 §9.1.3.5), so it exercises the reader's
    /// ephemeral private key and the *static* device key from the MSO — neither of which
    /// the Sign1 path touches.
    pub(crate) fn new_mac0(mdocs: impl IntoIterator<Item = Mdoc>) -> Self {
        Self::with_auth_type(mdocs, DeviceAuthType::Mac0)
    }

    fn with_auth_type(
        mdocs: impl IntoIterator<Item = Mdoc>,
        device_auth_type: DeviceAuthType,
    ) -> Self {
        let documents: std::collections::BTreeMap<String, Document> = mdocs
            .into_iter()
            .map(|mdoc| (mdoc.doc_type.clone(), Document::from(mdoc)))
            .collect();
        let documents: Documents = documents
            .try_into()
            .expect("TestExchange needs at least one mdoc");

        let (session_transcript, e_reader_key_private) = test_session_transcript();

        Self {
            session: TestDeviceSession {
                documents,
                session_transcript,
                device_auth_type,
            },
            device_key: Self::device_signing_key(),
            e_reader_key_private,
        }
    }

    pub(crate) fn session_transcript(&self) -> SessionTranscript180135 {
        self.session.session_transcript.clone()
    }

    /// The reader's ephemeral private key. Meaningful only for MAC0.
    ///
    /// [`device_authentication`]: super::authentication::mdoc::device_authentication
    pub(crate) fn e_reader_key_private(&self) -> [u8; 32] {
        self.e_reader_key_private
    }

    /// Produce a signed, plaintext response disclosing exactly `asks`.
    ///
    /// The holder is taken to permit everything requested; tests that care about partial
    /// disclosure should drive `prepare_response` themselves.
    pub(crate) fn respond(&self, asks: &[Ask]) -> DeviceResponse {
        let (requested, permitted) = build_request(asks);
        let mut prepared = self.session.prepare_response(&requested, permitted);
        self.sign_all(&mut prepared);
        prepared.finalize_response()
    }

    fn sign_all(&self, prepared: &mut PreparedDeviceResponse) {
        let e_mac_key = match self.session.device_auth_type {
            DeviceAuthType::Sign1 => None,
            DeviceAuthType::Mac0 => Some(self.e_mac_key()),
        };

        while let Some((_, payload)) = prepared
            .get_next_signature_payload()
            .map(|(id, payload)| (id, payload.to_vec()))
        {
            let tag = match &e_mac_key {
                None => {
                    let signature: Signature = self.device_key.sign(&payload);
                    signature.to_vec()
                }
                Some(key) => {
                    let mut mac = Hmac::<Sha256>::new_from_slice(key)
                        .expect("HMAC accepts keys of any length");
                    mac.update(&payload);
                    mac.finalize().into_bytes().to_vec()
                }
            };
            prepared.submit_next_signature(tag);
        }
    }

    /// EMacKey as the *device* computes it: `ECDH(SDeviceKey, EReaderKey)`.
    ///
    /// The reader arrives at the same value from the other side of the exchange —
    /// `ECDH(EReaderKey_private, device key from the MSO)` — which is precisely what a
    /// MAC0 test is for.
    fn e_mac_key(&self) -> [u8; 32] {
        let e_reader_key = self.session.session_transcript.1.clone().into_inner();
        let static_scalar: p256::NonZeroScalar =
            p256::SecretKey::from(self.device_key.clone()).into();
        let shared_secret =
            get_shared_secret(e_reader_key, &static_scalar).expect("ECDH with SDeviceKey failed");
        let transcript = Tag24::new(self.session.session_transcript.clone())
            .expect("failed to encode session transcript");
        derive_e_mac_key(&shared_secret, &transcript)
            .expect("failed to derive EMacKey")
            .into()
    }

    /// Mutable access to one document of a finalized response, for the mutators below.
    pub(crate) fn document_mut(
        response: &mut DeviceResponse,
        index: usize,
    ) -> &mut ResponseDocument {
        response
            .documents
            .as_mut()
            .expect("response has no documents")
            .iter_mut()
            .nth(index)
            .expect("no document at that index")
    }

    /// Append a byte-identical copy of document `index`.
    ///
    /// Two documents with the same doc type are legal in a published-18013-5 response
    /// (`documents` is an array), and the reader must evaluate both.
    pub(crate) fn duplicate_document(response: &mut DeviceResponse, index: usize) {
        let documents = response
            .documents
            .as_mut()
            .expect("response has no documents");
        let copy = documents
            .get(index)
            .expect("no document at that index")
            .clone();
        documents.push(copy);
    }
}

/// Turn a test's asks into the request/permission pair `prepare_response` wants.
pub(crate) fn build_request(asks: &[Ask]) -> (RequestedItems, PermittedItems) {
    let mut requested = Vec::new();
    let mut permitted = PermittedItems::new();

    for (doc_type, namespace, elements) in asks {
        let data_elements: DataElements = elements
            .iter()
            .map(|e| (e.to_string(), false))
            .collect::<std::collections::BTreeMap<_, _>>()
            .try_into()
            .expect("an ask must name at least one element");
        let namespaces: Namespaces = [(namespace.to_string(), data_elements)]
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>()
            .try_into()
            .expect("an ask must name a namespace");

        requested.push(ItemsRequest {
            doc_type: doc_type.to_string(),
            namespaces,
            request_info: None,
        });

        permitted
            .entry(doc_type.to_string())
            .or_default()
            .entry(namespace.to_string())
            .or_default()
            .extend(elements.iter().map(|e| e.to_string()));
    }

    (requested, permitted)
}

/// A structurally valid session transcript, and the reader's ephemeral private key.
///
/// Both sides of a test use this same value, so it does not need to correspond to a real
/// engagement — it only needs to be the *same* transcript the device signed over.
///
/// The reader private key is returned rather than discarded because MAC0 device
/// authentication needs it: the reader recomputes EMacKey with it.
pub(crate) fn test_session_transcript() -> (SessionTranscript180135, [u8; 32]) {
    let (_, device_public) = create_p256_ephemeral_keys().expect("failed to generate device key");
    let (reader_private, reader_public) =
        create_p256_ephemeral_keys().expect("failed to generate reader key");
    let reader_private: [u8; 32] = reader_private.to_bytes().into();

    let device_engagement = DeviceEngagement {
        version: "1.0".into(),
        security: Security(
            1,
            Tag24::new(device_public).expect("failed to encode device key"),
        ),
        device_retrieval_methods: None,
        server_retrieval_methods: None,
        protocol_info: None,
    };

    let transcript = SessionTranscript180135(
        Tag24::new(device_engagement).expect("failed to encode device engagement"),
        Tag24::new(reader_public).expect("failed to encode reader key"),
        Handover::QR,
    );

    (transcript, reader_private)
}

/// Relabel a document without touching what the issuer signed.
///
/// The MSO still says the original doc type, so this is what a doc-type mismatch looks
/// like on the wire.
pub(crate) fn set_document_doc_type(document: &mut ResponseDocument, doc_type: &str) {
    document.doc_type = doc_type.to_string();
}

/// Remove the certificate chain from the issuer-signed header.
pub(crate) fn strip_x5chain(document: &mut ResponseDocument) {
    document
        .issuer_signed
        .issuer_auth
        .unprotected
        .rest
        .retain(|(label, _)| label != &coset::Label::Int(X5CHAIN_COSE_HEADER_LABEL));
}

/// Corrupt the device signature so device authentication fails.
pub(crate) fn tamper_device_signature(document: &mut ResponseDocument) {
    match &mut document.device_signed.device_auth {
        DeviceAuth::DeviceSignature(sig) => flip_first_byte(&mut sig.inner.signature),
        DeviceAuth::DeviceMac(mac) => flip_first_byte(&mut mac.inner.tag),
    }
}

/// Replace a disclosed element's value, breaking its digest commitment.
pub(crate) fn tamper_element_value(
    document: &mut ResponseDocument,
    namespace: &str,
    element_identifier: &str,
    new_value: ciborium::Value,
) {
    let namespaces = document
        .issuer_signed
        .namespaces
        .as_mut()
        .expect("document discloses no namespaces");
    let (_, items) = namespaces
        .iter_mut()
        .find(|(ns, _)| ns.as_str() == namespace)
        .expect("document does not disclose that namespace");

    let target = items
        .iter_mut()
        .find(|item| item.as_ref().element_identifier == element_identifier)
        .expect("document does not disclose that element");

    let mut inner: IssuerSignedItem = target.as_ref().clone();
    inner.element_value = new_value;
    *target = IssuerSignedItemBytes::new(inner).expect("failed to re-encode tampered item");
}

fn flip_first_byte(bytes: &mut [u8]) {
    if let Some(byte) = bytes.first_mut() {
        *byte ^= 0xff;
    }
}

/// The reader half of a device-side test.
///
/// Performs the ECDH the real reader performs, then encrypts arbitrary
/// [`DeviceRequest`]s with the resulting `SKReader`. That is what makes it possible to
/// send the device things the library's own reader will never send — a request with
/// reader authentication, a bad version, `readerAuthAll`, or bytes that are not CBOR at
/// all.
pub(crate) struct TestReader {
    sk_reader: [u8; 32],
    counter: u32,
    session_transcript: SessionTranscript180135,
    e_reader_key: Tag24<crate::definitions::CoseKey>,
}

impl TestReader {
    /// Do the reader's half of the key agreement against an engaged device.
    pub(crate) fn engage(engaged: &SessionManagerEngaged) -> Self {
        let (private, public) =
            create_p256_ephemeral_keys().expect("failed to generate reader ephemeral key");
        let e_reader_key = Tag24::new(public).expect("failed to encode reader key");

        let e_device_key = engaged
            .device_engagement
            .as_ref()
            .security
            .1
            .clone()
            .into_inner();
        let shared_secret =
            get_shared_secret(e_device_key, &private.into()).expect("ECDH with the device failed");

        let session_transcript = SessionTranscript180135(
            engaged.device_engagement.clone(),
            e_reader_key.clone(),
            engaged.handover.clone(),
        );
        let transcript_bytes =
            Tag24::new(session_transcript.clone()).expect("failed to encode session transcript");
        let sk_reader = derive_session_key(&shared_secret, &transcript_bytes, true)
            .expect("failed to derive SKReader")
            .into();

        Self {
            sk_reader,
            counter: 0,
            session_transcript,
            e_reader_key,
        }
    }

    /// The first message of the session, carrying `request`.
    pub(crate) fn session_establishment(
        &mut self,
        request: &DeviceRequest,
    ) -> SessionEstablishment {
        let bytes = crate::cbor::to_vec(request).expect("failed to encode the device request");
        self.establishment_from_plaintext(&bytes)
    }

    /// As [`Self::session_establishment`], but the payload is whatever bytes you give it.
    pub(crate) fn establishment_from_plaintext(
        &mut self,
        plaintext: &[u8],
    ) -> SessionEstablishment {
        SessionEstablishment {
            data: self.encrypt(plaintext).into(),
            e_reader_key: self.e_reader_key.clone(),
        }
    }

    pub(crate) fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        crate::definitions::session::encrypt_reader_data(
            &self.sk_reader.into(),
            plaintext,
            &mut self.counter,
        )
        .expect("failed to encrypt the request")
    }

    /// A doc request with no reader authentication — what the library's reader sends.
    pub(crate) fn unauthenticated_doc_request(items_request: ItemsRequest) -> DocRequest {
        DocRequest {
            reader_auth: None,
            items_request: Tag24::new(items_request).expect("failed to encode the items request"),
        }
    }

    /// A doc request signed by `pki`'s reader certificate.
    ///
    /// With `valid: false` the certificate and its chain are untouched but the signature
    /// is garbage, which separates "the chain is not trusted" from "the signature does
    /// not verify" — two failures the holder used to be unable to tell apart, because
    /// neither reached it.
    pub(crate) fn signed_doc_request(
        &self,
        items_request: ItemsRequest,
        pki: &TestPki,
        valid: bool,
    ) -> DocRequest {
        let items_request = Tag24::new(items_request).expect("failed to encode the items request");

        let detached = crate::cbor::to_vec(
            &Tag24::new(ReaderAuthentication(
                "ReaderAuthentication".into(),
                self.session_transcript.clone(),
                items_request.clone(),
            ))
            .expect("failed to encode reader authentication"),
        )
        .expect("failed to encode reader authentication bytes");

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();
        let unprotected = coset::HeaderBuilder::new()
            .value(X5CHAIN_COSE_HEADER_LABEL, pki.x5chain().into_cbor())
            .build();
        let prepared = crate::cose::sign1::PreparedCoseSign1::new(
            coset::CoseSign1Builder::new()
                .protected(protected)
                .unprotected(unprotected),
            Some(&detached),
            None,
            false,
        )
        .expect("failed to prepare reader auth");

        let signature = if valid {
            let signature: Signature = pki.leaf_key.sign(prepared.signature_payload());
            signature.to_vec()
        } else {
            vec![0u8; 64]
        };

        DocRequest {
            reader_auth: Some(prepared.finalize(signature)),
            items_request,
        }
    }
}

/// A `DeviceRequest` asking for `age_over_21` in each of `doc_types`, with no reader auth.
pub(crate) fn unauthenticated_request(doc_types: &[&str]) -> DeviceRequest {
    let doc_requests: Vec<_> = doc_types
        .iter()
        .map(|doc_type| {
            TestReader::unauthenticated_doc_request(ItemsRequest::new(*doc_type, test_namespaces()))
        })
        .collect();

    DeviceRequest {
        version: DeviceRequest::VERSION.to_string(),
        doc_requests: doc_requests
            .try_into()
            .expect("a request needs at least one doc request"),
        device_request_info: None,
        reader_auth_all: None,
    }
}

/// `org.iso.18013.5.1` / `age_over_21`.
pub(crate) fn test_namespaces() -> Namespaces {
    Namespaces::new(
        "org.iso.18013.5.1".to_string(),
        DataElements::new("age_over_21".to_string(), false),
    )
}

/// The ISO photo ID doc type — a doc type that is not an mDL.
///
/// Defined by the Photo ID profile in Annex C of ISO/IEC TS 23220-4. Distinct from
/// [`PID_DOC_TYPE`]: an ISO photo ID and an EUDI Person Identification Data credential are
/// different credentials on different arcs, and neither is a passport. Used here only as a
/// credential the mDL rules were not written for.
pub(crate) const PHOTO_ID_DOC_TYPE: &str = "org.iso.23220.photoid.1";

/// The ISO/IEC 18013-5 mDL namespace.
pub(crate) const ISOMDL_NAMESPACE: &str = "org.iso.18013.5.1";

/// The EUDI PID doc type, which is also its namespace.
pub(crate) use crate::definitions::EUDI_PID_DOC_TYPE as PID_DOC_TYPE;

/// Taken from the shipped profile rather than restated, so a test cannot pass against an
/// OID the library does not actually use.
pub(crate) const EUDI_PID_DS_EKU: const_oid::ObjectIdentifier =
    crate::definitions::x509::validation::MdocProfile::EUDI_PID
        .issuer
        .document_signer_eku;

/// See [`EUDI_PID_DS_EKU`].
pub(crate) const EUDI_PID_READER_EKU: const_oid::ObjectIdentifier =
    crate::definitions::x509::validation::MdocProfile::EUDI_PID
        .reader
        .reader_auth_eku;

/// The five attributes the PID Rulebook makes mandatory for the mdoc encoding.
pub(crate) const PID_MANDATORY_ATTRIBUTES: [(&str, &str); 5] = [
    ("family_name", "Garcia"),
    ("given_name", "Ana"),
    ("birth_date", "1990-01-01"),
    ("birth_place", "Madrid"),
    ("nationality", "ES"),
];

pub(crate) fn eudi_pid_profile() -> crate::definitions::x509::validation::MdocProfile {
    crate::definitions::x509::validation::MdocProfile::EUDI_PID
}

/// A PID's issuance namespaces, carrying [`PID_MANDATORY_ATTRIBUTES`].
pub(crate) fn pid_namespaces() -> crate::issuance::Namespaces {
    [(
        PID_DOC_TYPE.to_string(),
        PID_MANDATORY_ATTRIBUTES
            .iter()
            .map(|(k, v)| (k.to_string(), ciborium::Value::Text(v.to_string())))
            .collect(),
    )]
    .into_iter()
    .collect()
}

/// A PKI whose document signer carries the PID EKU rather than the mDL one.
pub(crate) fn pid_pki() -> TestPki {
    TestPki::generate(
        TestPki::CRL_URL.to_string(),
        crate::definitions::x509::test::default_validity(),
        EUDI_PID_DS_EKU,
    )
}
