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
use elliptic_curve::{ecdh::EphemeralSecret, ecdh::SharedSecret, PublicKey};
use hkdf::Hkdf;
use hmac::SimpleHmac;
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
pub struct SessionTranscript(Tag24<DeviceEngagement>, Tag24<CoseKey>, Handover);

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
    #[error("42 characters is a valid length for the session key")]
    InvalidLength,
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
    e_device_key_priv: EphemeralSecret<NistP256>,
) -> Result<SharedSecret<NistP256>> {
    let encoded_point: EncodedPoint<NistP256> = EncodedPoint::<NistP256>::try_from(cose_key)?;
    let public_key = PublicKey::from_sec1_bytes(encoded_point.as_ref())?;
    let shared_secret = e_device_key_priv.diffie_hellman(&public_key);
    Ok(shared_secret)
}

pub fn get_session_transcript_bytes(
    public_key: CoseKey,
    device_engagement_bytes: DeviceEngagementBytes,
) -> Result<SessionTranscriptBytes> {
    let e_reader_key_bytes = Tag24::<CoseKey>::new(public_key)?;

    let session_transcript = SessionTranscript(
        device_engagement_bytes,
        e_reader_key_bytes,
        //Handover is always null for QRHandover
        Handover::QR,
    );

    let session_transcript_bytes = Tag24::<SessionTranscript>::new(session_transcript)?;
    Ok(session_transcript_bytes)
}

pub fn derive_session_key(
    shared_secret: &SharedSecret<NistP256>,
    public_key_reader: CoseKey,
    device_engagement_bytes: DeviceEngagementBytes,
    reader: bool,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let session_transcript_bytes =
        get_session_transcript_bytes(public_key_reader, device_engagement_bytes)?.inner_bytes;

    hasher.update(session_transcript_bytes);

    let hkdf: Hkdf<Sha256, SimpleHmac<Sha256>> =
        shared_secret.extract(Some(hasher.finalize().as_ref()));
    let mut okm = [0u8; 32];
    let sk_device = "SKDevice".as_bytes();
    let sk_reader = "SKReader".as_bytes();

    if reader {
        Hkdf::expand(&hkdf, sk_reader, &mut okm).map_err(|_e| Error::InvalidLength)?;

        Ok(okm)
    } else {
        Hkdf::expand(&hkdf, sk_device, &mut okm).map_err(|_e| Error::InvalidLength)?;

        Ok(okm)
    }
}

pub fn encrypt(
    session_key: [u8; 32],
    data: ByteStr,
    message_count: [u8; 4],
    reader: bool,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let initialization_vector = get_initialization_vector(message_count, reader)?;
    let key = GenericArray::from_slice(&session_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&initialization_vector);

    let ciphertext = cipher.encrypt(nonce, data.as_ref())?;

    Ok(ciphertext)
}

pub fn decrypt(
    session_key: [u8; 32],
    encrypted_data: Vec<u8>,
    message_count: [u8; 4],
    reader: bool,
) -> Result<ByteStr, aes_gcm::Error> {
    let initialization_vector = get_initialization_vector(message_count, reader)?;
    let nonce = Nonce::from_slice(&initialization_vector);
    let key = GenericArray::from_slice(&session_key);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher.decrypt(nonce, encrypted_data.as_ref())?;

    Ok(ByteStr::from(plaintext))
}

pub fn get_initialization_vector(
    message_count: [u8; 4],
    reader: bool,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let mdoc_reader_identifier: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mdoc_identifier: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

    let mut initialisation_vector: Vec<u8> = vec![];
    if reader {
        initialisation_vector.extend_from_slice(&mdoc_reader_identifier);
        initialisation_vector.extend_from_slice(&message_count);
    } else {
        initialisation_vector.extend_from_slice(&mdoc_identifier);
        initialisation_vector.extend_from_slice(&message_count);
    }

    Ok(initialisation_vector)
}

#[cfg(test)]
mod test {

    use crate::definitions::device_engagement::{CentralClientMode, DeviceRetrievalMethod};
    use crate::presentation::mdoc::prepare_device_engagement;

    use super::*;
    use crate::definitions::BleOptions;
    use byteorder::{BigEndian, ByteOrder};

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

        let device_shared_secret = get_shared_secret(pub_key_reader.clone(), device_keys.0)
            .expect("failed to derive secrets from public and private key");
        let reader_shared_secret = get_shared_secret(pub_key_device.clone(), reader_keys.0)
            .expect("failed to derive secret from public and private key");

        let uuid = uuid::Uuid::now_v1(&[0, 1, 2, 3, 4, 5]);

        let ble_option = BleOptions {
            peripheral_server_mode: None,
            central_client_mode: Some(CentralClientMode { uuid }),
        };

        let device_engagement_bytes = prepare_device_engagement(
            DeviceRetrievalMethod::BLE(ble_option),
            pub_key_reader.clone(),
        )
        .expect("failed to prepare for device engagement");

        let _session_key_device = derive_session_key(
            &device_shared_secret,
            pub_key_reader.clone(),
            device_engagement_bytes.clone(),
            false,
        )
        .unwrap();

        let session_key_reader = derive_session_key(
            &reader_shared_secret,
            pub_key_reader,
            device_engagement_bytes,
            true,
        )
        .unwrap();

        let message = "a message to encrypt!".as_bytes().to_vec();
        let msg = ByteStr::from(message);

        //encrypt with reader key
        let mut message_count_bytes = [0; 4];
        BigEndian::write_u32(&mut message_count_bytes, 1);

        let encrypted_message = encrypt(session_key_reader, msg.clone(), message_count_bytes, true);

        let decrypted_message = decrypt(
            session_key_reader,
            encrypted_message.unwrap(),
            message_count_bytes,
            true,
        );

        assert_eq!(msg, decrypted_message.unwrap());
    }
}
