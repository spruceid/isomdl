use super::helpers::Tag24;
use super::DeviceEngagement;
use crate::definitions::device_engagement::EReaderKeyBytes;
use crate::definitions::device_key::cose_key::EC2Y;
use crate::definitions::device_key::CoseKey;
use crate::definitions::device_key::EC2Curve;
use crate::definitions::helpers::bytestr::ByteStr;
use crate::definitions::session::EncodedPoints::{Ep256, Ep384};

use aes::cipher::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm,
    Nonce, // Or `Aes128Gcm`
};
use anyhow::Result;
use ecdsa::EncodedPoint;
use elliptic_curve::{
    ecdh::EphemeralSecret, ecdh::SharedSecret, generic_array::sequence::Concat, PublicKey,
};
use hkdf::Hkdf;
use p256::NistP256;
use p384::NistP384;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;
pub type DeviceEngagementBytes = Tag24<DeviceEngagement>;
pub type SessionTranscriptBytes = Tag24<SessionTranscript>;
pub type NfcHandover = (ByteStr, Option<ByteStr>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEstablishment {
    pub e_reader_key: EReaderKeyBytes,
    pub data: ByteStr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub data: Option<ByteStr>,
    pub status: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTranscript(
    pub Tag24<DeviceEngagement>,
    pub Tag24<CoseKey>,
    pub Handover,
);

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Curve not supported for DH exchange")]
    UnsupportedCurve,
    #[error("Not a NistP256 Shared Secret")]
    SharedSecretError,
    #[error("Could not derive Shared Secret")]
    SessionKeyError,
    #[error("Something went wrong generating ephemeral keys")]
    EphemeralKeyError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "Option<NfcHandover>", into = "Option<NfcHandover>")]
pub enum Handover {
    QR,
    NFC(NfcHandover),
}

pub enum EphemeralSecrets {
    Eph256(EphemeralSecret<NistP256>),
    Eph384(EphemeralSecret<NistP384>),
}

pub enum EncodedPoints {
    Ep256(EncodedPoint<NistP256>),
    Ep384(EncodedPoint<NistP384>),
}

pub enum SharedSecrets {
    Ss256(SharedSecret<NistP256>),
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

impl From<Option<NfcHandover>> for Handover {
    fn from(o: Option<NfcHandover>) -> Handover {
        match o {
            Some(nfc) => Handover::NFC(nfc),
            None => Handover::QR,
        }
    }
}

impl From<Handover> for Option<NfcHandover> {
    fn from(h: Handover) -> Option<NfcHandover> {
        match h {
            Handover::NFC(nfc) => Some(nfc),
            Handover::QR => None,
        }
    }
}

pub fn create_p256_ephemeral_keys() -> Result<(EphemeralSecret<NistP256>, CoseKey), Error> {
    let private_key = p256::ecdh::EphemeralSecret::random(&mut OsRng);

    let encoded_point = ecdsa::EncodedPoint::<NistP256>::from(private_key.public_key());
    let x_coordinate = encoded_point.x().ok_or(Error::EphemeralKeyError)?;
    let y_coordinate = encoded_point.y().ok_or(Error::EphemeralKeyError)?;

    let crv = EC2Curve::try_from(1).map_err(|_e| Error::EphemeralKeyError)?;
    let public_key = CoseKey::EC2 {
        crv,
        x: x_coordinate.to_vec(),
        y: EC2Y::Value(y_coordinate.to_vec()),
    };

    Ok((private_key, public_key))
}

pub fn get_shared_secret(
    cose_key: CoseKey,
    e_device_key_priv: &EphemeralSecret<NistP256>,
) -> Result<SharedSecret<NistP256>> {
    let encoded_point: EncodedPoint<NistP256> = EncodedPoint::<NistP256>::try_from(cose_key)?;
    let public_key = PublicKey::from_sec1_bytes(encoded_point.as_ref())?;
    let shared_secret = e_device_key_priv.diffie_hellman(&public_key);
    Ok(shared_secret)
}

pub fn derive_session_key(
    shared_secret: &SharedSecret<NistP256>,
    session_transcript: &Tag24<SessionTranscript>,
    reader: bool,
) -> Aes256Gcm {
    let salt = Sha256::digest(&session_transcript.inner_bytes);
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

    Aes256Gcm::new(&okm.into())
}

pub fn encrypt_mdoc_data(
    sk_device: &Aes256Gcm,
    ciphertext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    encrypt(sk_device, ciphertext, message_count, false)
}

pub fn encrypt_reader_data(
    sk_reader: &Aes256Gcm,
    ciphertext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    encrypt(sk_reader, ciphertext, message_count, true)
}

fn encrypt(
    session_key: &Aes256Gcm,
    plaintext: &[u8],
    message_count: &mut u32,
    reader: bool,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let initialization_vector = get_initialization_vector(message_count, reader);
    let nonce = Nonce::from(initialization_vector);
    session_key.encrypt(&nonce, plaintext)
}

pub fn decrypt_mdoc_data(
    sk_device: &Aes256Gcm,
    ciphertext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    decrypt(sk_device, ciphertext, message_count, false)
}

pub fn decrypt_reader_data(
    sk_reader: &Aes256Gcm,
    ciphertext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    decrypt(sk_reader, ciphertext, message_count, true)
}

fn decrypt(
    session_key: &Aes256Gcm,
    ciphertext: &[u8],
    message_count: &mut u32,
    reader: bool,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let initialization_vector = get_initialization_vector(message_count, reader);
    let nonce = Nonce::from(initialization_vector);
    session_key.decrypt(&nonce, ciphertext)
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
    use crate::definitions::device_engagement::Security;

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

        let device_shared_secret = get_shared_secret(pub_key_reader.clone(), &device_keys.0)
            .expect("failed to derive secrets from public and private key");
        let reader_shared_secret = get_shared_secret(pub_key_device.clone(), &reader_keys.0)
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
        let session_transcript = Tag24::new(SessionTranscript(
            device_engagement_bytes,
            reader_key_bytes,
            Handover::QR,
        ))
        .unwrap();
        let _session_key_device =
            derive_session_key(&device_shared_secret, &session_transcript, false);

        let session_key_reader =
            derive_session_key(&reader_shared_secret, &session_transcript, true);

        let plaintext = "a message to encrypt!".as_bytes();

        let mut message_count = 0;

        let ciphertext =
            encrypt_reader_data(&session_key_reader, plaintext, &mut message_count).unwrap();

        let mut message_count = 0;

        let decrypted_plaintext =
            decrypt_reader_data(&session_key_reader, &ciphertext, &mut message_count).unwrap();

        assert_eq!(plaintext, decrypted_plaintext);
    }
}
