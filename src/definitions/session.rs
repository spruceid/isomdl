use super::helpers::Tag24;
use super::DeviceEngagement;
use crate::definitions::device_engagement::EReaderKeyBytes;
use crate::definitions::device_key::cose_key::EC2Y;
use crate::definitions::device_key::CoseKey;
use crate::definitions::device_key::EC2Curve;
use crate::definitions::helpers::bytestr::ByteStr;
use crate::definitions::session::EncodedPoints::{Ep256, Ep384};
pub use aes::cipher::generic_array::typenum::U8;
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
use serde_cbor::Value as CborValue;
use sha2::Sha256;

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;
pub type DeviceEngagementBytes = Tag24<DeviceEngagement>;
pub type SessionTranscriptBytes = Tag24<SessionTranscript>;
pub type NfcHandover = (String, Option<String>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEstablishment {
    e_reader_key: EReaderKeyBytes,
    data: ByteStr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    data: ByteStr,
    status: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(try_from = "CborValue")]
pub struct SessionTranscript(
    Tag24<DeviceEngagement>,
    Tag24<CoseKey>,
    Option<Tag24<ByteStr>>,
);

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Curve not supported for DH exchange")]
    UnsupportedCurve,
    #[error("Not a NistP256 Shared Secret")]
    SharedSecretError,
}

pub enum Handover {
    QRHANDOVER(Option<Vec<u8>>),
    NFCHANDOVER(Option<Vec<u8>>),
}

#[derive(Debug, Clone)]
pub enum Curves {
    P256,
    P384,
    P521,
    X25519,
    X448,
    Ed25519,
    Ed448,
}

pub enum EphemeralSecrets {
    Eph256(EphemeralSecret<NistP256>),
    Eph384(EphemeralSecret<NistP384>),
}

pub enum EncodedPoints {
    Ep256(EncodedPoint<NistP256>),
    Ep384(EncodedPoint<NistP384>),
}

impl Into<Vec<u8>> for EncodedPoints {
    fn into(self) -> Vec<u8> {
        match self {
            Ep256(encoded_point) => encoded_point.as_bytes().to_vec(),
            Ep384(encoded_point) => encoded_point.as_bytes().to_vec(),
        }
    }
}

pub enum SharedSecrets {
    Ss256(SharedSecret<NistP256>),
    Ss384(SharedSecret<NistP384>),
}

pub fn generate_ephemeral_keys(crv: Curves) -> Result<(EphemeralSecrets, EncodedPoints), Error> {
    //return  EDeviceKey.Priv/EReaderKey.Priv, EDeviceKey.Pub/EReaderKey.Pub
    match crv {
        Curves::P256 => {
            let e_device_key_priv = p256::ecdh::EphemeralSecret::random(&mut OsRng);
            let e_device_key_pub_bytes =
                ecdsa::EncodedPoint::<NistP256>::from(e_device_key_priv.public_key());
            Ok((
                EphemeralSecrets::Eph256(e_device_key_priv),
                EncodedPoints::Ep256(e_device_key_pub_bytes),
            ))
        }
        Curves::P384 => {
            let e_device_key_priv = p384::ecdh::EphemeralSecret::random(&mut OsRng);
            let e_device_key_pub_bytes =
                ecdsa::EncodedPoint::<NistP384>::from(e_device_key_priv.public_key());
            Ok((
                EphemeralSecrets::Eph384(e_device_key_priv),
                EncodedPoints::Ep384(e_device_key_pub_bytes),
            ))
        }
        _ => Err(Error::UnsupportedCurve),
    }
}

pub fn create_p256_ephemeral_keys() -> Result<(EphemeralSecret<NistP256>, CoseKey), Error> {
    let private_key = p256::ecdh::EphemeralSecret::random(&mut OsRng);

    let encoded_point = ecdsa::EncodedPoint::<NistP256>::from(private_key.public_key());
    let x_coordinate = encoded_point
        .x()
        .expect("something went wrong generating keys");
    let y_coordinate = encoded_point
        .y()
        .expect("something went wrong generating keys");

    let crv = EC2Curve::try_from(1).expect("provide mapped integer for curve");
    let public_key = CoseKey::EC2 {
        crv: crv,
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
        None,
    );

    let session_transcript_bytes = Tag24::<SessionTranscript>::new(session_transcript)?;
    Ok(session_transcript_bytes)
}

pub fn derive_session_key(shared_secret: SharedSecret<NistP256>, reader: bool) -> [u8; 42] {
    //Todo: add salt

    let hkdf: Hkdf<Sha256, SimpleHmac<Sha256>> = shared_secret.extract(None);
    let mut okm = [0u8; 42];
    let sk_device = "SKDevice".as_bytes();
    let sk_reader = "SKReader".as_bytes();

    if reader == true {
        Hkdf::expand(&hkdf, sk_reader, &mut okm)
            .expect("42 characters is a valid length for the session key");

        okm
    } else {
        Hkdf::expand(&hkdf, sk_device, &mut okm)
            .expect("42 characters is a valid length for the session key");

        okm
    }
}

pub fn encrypt(session_key: [u8; 42], sessionData: SessionData) {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let generic_array: GenericArray<_, U8> = GenericArray::clone_from_slice(&session_key[0..42]);
    //let cipher = Aes256Gcm::new(&generic_array);
    //let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    //let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())?;
    //let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
}

pub fn decrypt() {}

#[cfg(test)]
mod test {

    use crate::definitions::DeviceEngagement;

    use super::*;

    #[test]
    fn key_generation() {
        generate_ephemeral_keys(Curves::P384).expect("failed to generate keys");
    }

    #[test]
    fn test_derive_session_key() {
        let reader_keys = create_p256_ephemeral_keys().expect("failed to generate reader keys");
        let device_keys = create_p256_ephemeral_keys().expect("failed to generate device keys");
        let pub_key_reader = reader_keys.1;
        let pub_key_device = device_keys.1;
        let device_shared_secret = get_shared_secret(pub_key_reader, device_keys.0)
            .expect("failed to derive secrets from public and private key");
        let reader_shared_secret = get_shared_secret(pub_key_device, reader_keys.0)
            .expect("failed to derive secret from public and private key");
        let session_key_device = derive_session_key(device_shared_secret, false);
        println!("session_key_device: {:?}", session_key_device);

        let session_key_reader = derive_session_key(reader_shared_secret, true);
        println!("session_key_reader: {:?}", session_key_reader);
    }
}
