//! This module contains the definitions and functions related to session establishment and management.
//!
//! The [get_initialization_vector] function generates an initialization vector for encryption/decryption
//! based on a message count and a flag indicating whether the vector is for the reader or the device.
use super::helpers::Tag24;
use super::DeviceEngagement;
use crate::cbor::CborError;

use crate::definitions::device_engagement::EReaderKeyBytes;
use crate::definitions::device_key::cose_key::EC2Y;
use crate::definitions::device_key::CoseKey;
use crate::definitions::device_key::EC2Curve;
use crate::definitions::helpers::bytestr::ByteStr;
use crate::definitions::session::EncodedPoints::{Ep256, Ep384};

use aes::cipher::{generic_array::GenericArray, typenum::U32};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce, // Or `Aes128Gcm`
};
use anyhow::Result;
use ecdsa::EncodedPoint;
use elliptic_curve::{
    ecdh::EphemeralSecret, ecdh::SharedSecret, generic_array::sequence::Concat,
    sec1::FromEncodedPoint,
};
use hkdf::Hkdf;
use ndef_rs::error::NdefError;
use p256::NistP256;
use p384::NistP384;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;
pub type DeviceEngagementBytes = Tag24<DeviceEngagement>;
pub type SessionTranscriptBytes = Tag24<SessionTranscript180135>;

/// Represents the establishment of a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEstablishment {
    /// The EReader key used for session establishment.
    pub e_reader_key: EReaderKeyBytes,

    /// The data associated with the session establishment.
    pub data: ByteStr,
}

/// Represents session data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// An optional [ByteStr] that represents the data associated with the session.
    /// The field is skipped during serialization if it is [None].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ByteStr>,

    /// An optional [Status] that represents the status of the session.
    /// Similarly, the field is skipped during serialization if it is [None].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub enum Status {
    SessionEncryptionError,
    CborDecodingError,
    SessionTermination,
}

impl From<Status> for u64 {
    fn from(s: Status) -> u64 {
        match s {
            Status::SessionEncryptionError => 10,
            Status::CborDecodingError => 11,
            Status::SessionTermination => 20,
        }
    }
}

impl TryFrom<u64> for Status {
    type Error = String;

    fn try_from(n: u64) -> Result<Status, String> {
        match n {
            10 => Ok(Status::SessionEncryptionError),
            11 => Ok(Status::CborDecodingError),
            20 => Ok(Status::SessionTermination),
            _ => Err(format!("unrecognised error code: {n}")),
        }
    }
}

pub trait SessionTranscript: Serialize + for<'a> Deserialize<'a> {}

/// Represents the device engagement bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTranscript180135(
    pub DeviceEngagementBytes,
    pub Tag24<EReaderKey>,
    pub Handover,
);

impl SessionTranscript for SessionTranscript180135 {}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Curve not supported for DH exchange")]
    UnsupportedCurve,
    #[error("Not a NistP256 Shared Secret")]
    SharedSecretError,
    #[error("Could not derive Shared Secret")]
    SessionKeyError,
    #[error("Something went wrong generating ephemeral keys")]
    EphemeralKeyError,
    #[error("Failed to encode a session structure: {0}")]
    Tag24(#[from] super::helpers::tag24::Error),
    #[error("Serialization error")]
    Cbor(#[from] CborError),
    #[error("NFC negotiation error")]
    Ndef(#[from] NdefError),
    // I don't like using anyhow in an API, but ndef_rs itself returns anyhow errors.
    #[error("Failed serializing NFC NDEF message")]
    NdefSerialization(anyhow::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Handover {
    QR,
    NFC(ByteStr, Option<ByteStr>),
    OID4VP(String, String),
}

pub enum EphemeralSecrets {
    /// Represents an Eph256 session.
    /// This enum variant holds an `EphemeralSecret` of type `NistP256`.
    Eph256(EphemeralSecret<NistP256>),

    /// Represents an ephemeral secret using the NIST P-384 elliptic curve.
    Eph384(EphemeralSecret<NistP384>),
}

pub enum EncodedPoints {
    /// Represents a session with an Ep256 encoded point.
    Ep256(EncodedPoint<NistP256>),

    /// Represents an Ep384 session.
    /// This struct holds an encoded point of type `EncodedPoint<NistP384>`.
    Ep384(EncodedPoint<NistP384>),
}

pub enum SharedSecrets {
    /// Represents a session with a shared secret using the `SS256` algorithm.
    /// The shared secret is generated using the `NistP256` elliptic curve.
    Ss256(SharedSecret<NistP256>),

    /// Represents a session with a shared secret using the `Ss384` algorithm.
    /// The shared secret is of type [`SharedSecret<NistP384>`].
    Ss384(SharedSecret<NistP384>),
}

impl From<EncodedPoints> for Vec<u8> {
    fn from(ep: EncodedPoints) -> Vec<u8> {
        match ep {
            Ep256(encoded_point) => encoded_point.as_bytes().to_vec(),
            Ep384(encoded_point) => encoded_point.as_bytes().to_vec(),
        }
    }
}

pub(crate) fn create_p256_ephemeral_keys() -> Result<(p256::SecretKey, CoseKey), Error> {
    let private_key = p256::SecretKey::random(&mut OsRng);
    let public_key = p256_cose_key(&private_key.public_key())?;
    Ok((private_key, public_key))
}

pub(crate) fn get_shared_secret(
    peer_key: CoseKey,
    private_key: &p256::NonZeroScalar,
) -> Result<SharedSecret<NistP256>> {
    let encoded_point: EncodedPoint<NistP256> = EncodedPoint::<NistP256>::try_from(peer_key)?;
    let public_key: Option<p256::PublicKey> =
        p256::PublicKey::from_encoded_point(&encoded_point).into();
    let public_key = public_key
        .ok_or_else(|| anyhow::anyhow!("the peer's public key could not be constructed"))?;
    let shared_secret = p256::ecdh::diffie_hellman(private_key, public_key.as_affine());
    Ok(shared_secret)
}

/// The private half of an ephemeral session key (ISO/IEC 18013-5 §12.2.4): EReaderKey.Priv
/// on the reader side, EDeviceKey.Priv on the mdoc side.
///
/// Both sides use it to derive the session encryption keys. The reader also uses it to
/// verify COSE_Mac0 device authentication.
///
/// Serialized as `{ "crv": <curve>, "d": <private scalar> }`. `Debug` does not show the key.
#[derive(Clone)]
pub enum EphemeralPrivateKey {
    P256(p256::SecretKey),
}

impl std::fmt::Debug for EphemeralPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P256(_) => f.write_str("EphemeralPrivateKey::P256(..)"),
        }
    }
}

impl EphemeralPrivateKey {
    /// Generate a new P-256 key. Returns the key and its public half.
    pub fn generate_p256() -> Result<(Self, CoseKey), Error> {
        let (private_key, public_key) = create_p256_ephemeral_keys()?;
        Ok((Self::P256(private_key), public_key))
    }

    pub fn public_key(&self) -> Result<CoseKey, Error> {
        match self {
            EphemeralPrivateKey::P256(key) => p256_cose_key(&key.public_key()),
        }
    }

    /// ECDH with the other side's ephemeral public key (EDeviceKey for the reader,
    /// EReaderKey for the mdoc), to derive the session keys.
    pub fn session_shared_secret(&self, peer_key: CoseKey) -> Result<SharedSecret<NistP256>> {
        match self {
            EphemeralPrivateKey::P256(key) => get_shared_secret(peer_key, &key.to_nonzero_scalar()),
        }
    }

    /// Derive EMacKey, as the reader, for COSE_Mac0 device authentication (ISO/IEC
    /// 18013-5 §12.4.5).
    ///
    /// `s_device_key` is the mdoc authentication key from the MSO. It must be on the same
    /// curve as this key.
    pub(crate) fn e_mac_key<T: Serialize>(
        &self,
        s_device_key: CoseKey,
        session_transcript: &Tag24<T>,
    ) -> Result<GenericArray<u8, U32>> {
        match self {
            EphemeralPrivateKey::P256(key) => {
                if !matches!(
                    s_device_key,
                    CoseKey::EC2 {
                        crv: EC2Curve::P256,
                        ..
                    }
                ) {
                    return Err(anyhow::anyhow!(
                        "the mdoc authentication key is not on the reader key's curve (P-256)"
                    ));
                }
                let shared_secret = get_shared_secret(s_device_key, &key.to_nonzero_scalar())?;
                derive_e_mac_key(&shared_secret, session_transcript)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "crv")]
enum EphemeralPrivateKeyRepr {
    #[serde(rename = "P-256")]
    P256 {
        #[serde(with = "serde_bytes")]
        d: [u8; 32],
    },
}

impl Serialize for EphemeralPrivateKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::P256(key) => EphemeralPrivateKeyRepr::P256 {
                d: key.to_bytes().into(),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for EphemeralPrivateKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match EphemeralPrivateKeyRepr::deserialize(deserializer)? {
            EphemeralPrivateKeyRepr::P256 { d } => p256::SecretKey::from_bytes(&d.into())
                .map(Self::P256)
                .map_err(serde::de::Error::custom),
        }
    }
}

fn p256_cose_key(public_key: &p256::PublicKey) -> Result<CoseKey, Error> {
    let encoded_point = ecdsa::EncodedPoint::<NistP256>::from(public_key);
    let x_coordinate = encoded_point.x().ok_or(Error::EphemeralKeyError)?;
    let y_coordinate = encoded_point.y().ok_or(Error::EphemeralKeyError)?;
    let crv = EC2Curve::try_from(1).map_err(|_e| Error::EphemeralKeyError)?;
    Ok(CoseKey::EC2 {
        crv,
        x: x_coordinate.to_vec(),
        y: EC2Y::Value(y_coordinate.to_vec()),
    })
}

pub fn derive_session_key(
    shared_secret: &SharedSecret<NistP256>,
    session_transcript: &SessionTranscriptBytes,
    reader: bool,
) -> Result<GenericArray<u8, U32>> {
    let salt = Sha256::digest(
        crate::cbor::to_vec(session_transcript)
            .map_err(|e| anyhow::anyhow!("failed to serialize session transcript: {e}"))?,
    );
    let hkdf = shared_secret.extract::<Sha256>(Some(salt.as_ref()));
    let mut okm = [0u8; 32];
    let sk_device = "SKDevice".as_bytes();
    let sk_reader = "SKReader".as_bytes();

    // Safe to unwrap as error will only occur if okm.len() is greater than 255 * 32;
    if reader {
        Hkdf::expand(&hkdf, sk_reader, &mut okm).unwrap();
    } else {
        Hkdf::expand(&hkdf, sk_device, &mut okm).unwrap();
    }

    Ok(okm.into())
}

/// Derive the EMacKey from the shared secret per ISO 18013-5 section 9.1.3.5.
///
/// The EMacKey is used for HMAC-based device authentication (COSE_Mac0) as an
/// alternative to ECDSA-based device authentication (COSE_Sign1).
///
/// The shared secret must be derived using ECDH with the mdoc authentication key (SDeviceKey)
/// and the reader's ephemeral key (EReaderKey), not the ephemeral device session key.
pub fn derive_e_mac_key<T: serde::Serialize>(
    shared_secret: &SharedSecret<NistP256>,
    session_transcript: &Tag24<T>,
) -> Result<GenericArray<u8, U32>> {
    let salt = Sha256::digest(
        crate::cbor::to_vec(session_transcript)
            .map_err(|e| anyhow::anyhow!("failed to serialize session transcript: {e}"))?,
    );
    let hkdf = shared_secret.extract::<Sha256>(Some(salt.as_ref()));
    let mut okm = [0u8; 32];
    Hkdf::expand(&hkdf, b"EMacKey", &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(okm.into())
}

pub fn encrypt_device_data(
    sk_device: &GenericArray<u8, U32>,
    plaintext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    encrypt(sk_device, plaintext, message_count, false)
}

pub fn encrypt_reader_data(
    sk_reader: &GenericArray<u8, U32>,
    plaintext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    encrypt(sk_reader, plaintext, message_count, true)
}

fn encrypt(
    session_key: &GenericArray<u8, U32>,
    plaintext: &[u8],
    message_count: &mut u32,
    reader: bool,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let initialization_vector = get_initialization_vector(message_count, reader);
    let nonce = Nonce::from(initialization_vector);
    Aes256Gcm::new(session_key).encrypt(&nonce, plaintext)
}

pub fn decrypt_device_data(
    sk_device: &GenericArray<u8, U32>,
    ciphertext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    decrypt(sk_device, ciphertext, message_count, false)
}

pub fn decrypt_reader_data(
    sk_reader: &GenericArray<u8, U32>,
    ciphertext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    decrypt(sk_reader, ciphertext, message_count, true)
}

fn decrypt(
    session_key: &GenericArray<u8, U32>,
    ciphertext: &[u8],
    message_count: &mut u32,
    reader: bool,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let initialization_vector = get_initialization_vector(message_count, reader);
    let nonce = Nonce::from(initialization_vector);
    Aes256Gcm::new(session_key).decrypt(&nonce, ciphertext)
}

pub fn get_initialization_vector(message_count: &mut u32, reader: bool) -> [u8; 12] {
    *message_count += 1;
    let counter = GenericArray::from(message_count.to_be_bytes());
    let identifier = if reader {
        GenericArray::from([0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8])
    } else {
        GenericArray::from([0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8])
    };

    identifier.concat(counter).into()
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::cbor;
    use crate::definitions::device_engagement::Security;
    use crate::definitions::device_request::DeviceRequest;

    #[test]
    fn ephemeral_private_key_debug_hides_the_key() {
        let (key, _) = EphemeralPrivateKey::generate_p256().unwrap();
        assert_eq!(format!("{key:?}"), "EphemeralPrivateKey::P256(..)");
    }

    #[test]
    fn ephemeral_private_key_is_stored_with_its_curve() {
        let (key, public_key) = EphemeralPrivateKey::generate_p256().unwrap();
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json["crv"], "P-256");

        let back: EphemeralPrivateKey = serde_json::from_value(json).unwrap();
        assert_eq!(back.public_key().unwrap(), public_key);
    }

    #[test]
    fn ephemeral_private_key_refuses_invalid_bytes() {
        let zero = serde_json::json!({ "crv": "P-256", "d": vec![0u8; 32] });
        assert!(serde_json::from_value::<EphemeralPrivateKey>(zero).is_err());
        let short = serde_json::json!({ "crv": "P-256", "d": vec![1u8; 31] });
        assert!(serde_json::from_value::<EphemeralPrivateKey>(short).is_err());
    }

    #[test]
    fn qr_handover() {
        // null
        let cbor = hex::decode("F6").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR) {
            panic!("expected 'Handover::QR', received {handover:?}")
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    #[should_panic]
    fn qr_handover_empty_array() {
        // []
        let cbor = hex::decode("80").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR) {
            panic!("expected 'Handover::QR', received {handover:?}")
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    #[should_panic]
    fn qr_handover_empty_object() {
        // {}
        let cbor = hex::decode("A0").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR) {
            panic!("expected 'Handover::QR', received {handover:?}")
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    fn oid4vp_handover() {
        // ["aud", "nonce"]
        let cbor = hex::decode("8263617564656E6F6E6365").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::OID4VP(..)) {
            panic!(
                "expected '{}', received {:?}",
                "Handover::OID4VP(..)", handover
            )
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    fn key_generation() {
        //todo fully test the exchange of keys and the resulting session keys e2e
        create_p256_ephemeral_keys().expect("failed to generate keys");
    }

    #[test]
    fn test_encryption_decryption() {
        let reader_keys = create_p256_ephemeral_keys().expect("failed to generate reader keys");
        let device_keys = create_p256_ephemeral_keys().expect("failed to generate device keys");
        let pub_key_reader = reader_keys.1;
        let pub_key_device = device_keys.1;

        let device_shared_secret =
            get_shared_secret(pub_key_reader.clone(), &device_keys.0.to_nonzero_scalar())
                .expect("failed to derive secrets from public and private key");
        let reader_shared_secret =
            get_shared_secret(pub_key_device.clone(), &reader_keys.0.to_nonzero_scalar())
                .expect("failed to derive secret from public and private key");

        let device_key_bytes = Tag24::new(pub_key_device).unwrap();
        let reader_key_bytes = Tag24::new(pub_key_reader).unwrap();

        let device_engagement = DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, device_key_bytes),
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        };

        let device_engagement_bytes = Tag24::new(device_engagement).unwrap();
        let session_transcript = Tag24::new(SessionTranscript180135(
            device_engagement_bytes,
            reader_key_bytes,
            Handover::QR,
        ))
        .unwrap();
        let _session_key_device =
            derive_session_key(&device_shared_secret, &session_transcript, false).unwrap();

        let session_key_reader =
            derive_session_key(&reader_shared_secret, &session_transcript, true).unwrap();

        let plaintext = "a message to encrypt!".as_bytes();

        let mut message_count = 0;

        let ciphertext =
            encrypt_reader_data(&session_key_reader, plaintext, &mut message_count).unwrap();

        let mut message_count = 0;

        let decrypted_plaintext =
            decrypt_reader_data(&session_key_reader, &ciphertext, &mut message_count).unwrap();

        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn handle_session_establishment_and_decrypt_device_request() {
        const E_DEVICE_KEY: &str = include_str!("../../test/definitions/session/e_device_key.cbor");
        const SESSION_ESTABLISHMENT: &str =
            include_str!("../../test/definitions/session/session_establishment.cbor");
        const SHARED_SECRET: &str =
            include_str!("../../test/definitions/session/shared_secret.cbor");
        const SESSION_TRANSCRIPT: &str =
            include_str!("../../test/definitions/session/session_transcript.cbor");
        const READER_SESSION_KEY: &str =
            include_str!("../../test/definitions/session/reader_session_key.cbor");

        let e_device_key_bytes = hex::decode(E_DEVICE_KEY).unwrap();
        let e_device_key = p256::SecretKey::from_slice(&e_device_key_bytes).unwrap();
        let e_device_key_inner = e_device_key.to_nonzero_scalar();

        let session_establishment_bytes = hex::decode(SESSION_ESTABLISHMENT).unwrap();
        let session_establishment: SessionEstablishment =
            cbor::from_slice(&session_establishment_bytes).unwrap();

        let e_reader_key = session_establishment.e_reader_key;
        let encrypted_request = session_establishment.data;

        let shared_secret =
            get_shared_secret(e_reader_key.as_ref().clone(), &e_device_key_inner).unwrap();
        let shared_secret_hex = hex::encode(shared_secret.raw_secret_bytes());
        assert_eq!(shared_secret_hex, SHARED_SECRET);

        let session_transcript_bytes = hex::decode(SESSION_TRANSCRIPT).unwrap();
        let session_transcript: SessionTranscriptBytes =
            cbor::from_slice(&session_transcript_bytes).unwrap();

        let session_key = derive_session_key(&shared_secret, &session_transcript, true).unwrap();
        let session_key_hex = hex::encode(session_key);
        assert_eq!(session_key_hex, READER_SESSION_KEY);

        let plaintext =
            decrypt_reader_data(&session_key, encrypted_request.as_ref(), &mut 0).unwrap();
        let _device_request: DeviceRequest = crate::cbor::from_slice(&plaintext).unwrap();
    }
}
