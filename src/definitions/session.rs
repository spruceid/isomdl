use crate::definitions::helpers::bytestr::ByteStr;
use crate::device_engagement::EReaderKeyBytes;
use crate::mdoc::CoseKey;
use crate::session::EphemeralSecrets::{ES256, ES384};
use anyhow::Result;
use ecdsa::EncodedPoint;
use elliptic_curve::{ecdh::EphemeralSecret, ecdh::SharedSecret, PublicKey};
use p256::NistP256;
use p384::NistP384;
use rand_core::OsRng; // requires 'getrandom' feature

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;
pub type DeviceEngagementBytes = Vec<u8>;
pub type SessionTranscript = (DeviceEngagementBytes, EReaderKeyBytes, Handover);
pub type NfcHandover = (String, Option<String>);

pub struct SessionEstablishment {
    e_reader_key: EReaderKey,
    data: ByteStr,
}

pub struct SessionData {
    data: ByteStr,
    status: u64,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Curve not supported for DH exchange")]
    UnsupportedCurve,
}

pub enum Handover {
    QRHANDOVER,
    NFCHANDOVER,
}

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
    ES256(EphemeralSecret<NistP256>),
    ES384(EphemeralSecret<NistP384>),
}

pub enum EncodedPoints {
    NistP256(EncodedPoint<NistP256>),
    NistP384(EncodedPoint<NistP384>),
}

pub enum SharedSecrets {
    NistP256(SharedSecret<NistP256>),
    NistP384(SharedSecret<NistP384>),
}

pub fn generate_ephemeral_keys(crv: Curves) -> Result<(EphemeralSecrets, EncodedPoints), Error> {
    //return  EDeviceKey.Priv, EDeviceKey.Pub and a cipher suite identifier
    match crv {
        Curves::P256 => {
            let e_device_key_priv = p256::ecdh::EphemeralSecret::random(&mut OsRng);
            let e_device_key_pub_bytes =
                ecdsa::EncodedPoint::<NistP256>::from(e_device_key_priv.public_key());
            Ok((
                EphemeralSecrets::ES256(e_device_key_priv),
                EncodedPoints::NistP256(e_device_key_pub_bytes),
            ))
        }
        Curves::P384 => {
            let e_device_key_priv = p384::ecdh::EphemeralSecret::random(&mut OsRng);
            let e_device_key_pub_bytes =
                ecdsa::EncodedPoint::<NistP384>::from(e_device_key_priv.public_key());
            Ok((
                EphemeralSecrets::ES384(e_device_key_priv),
                EncodedPoints::NistP384(e_device_key_pub_bytes),
            ))
        }
        _ => Err(Error::UnsupportedCurve),
    }
}

pub fn derive_shared_secret(
    encoded_point: Vec<u8>,
    e_device_key_priv: EphemeralSecrets,
) -> Result<SharedSecrets> {
    match e_device_key_priv {
        ES256(private_key) => {
            let public_key = PublicKey::from_sec1_bytes(encoded_point.as_ref())?;
            let shared_secret = private_key.diffie_hellman(&public_key);

            Ok(SharedSecrets::NistP256(shared_secret))
        }
        ES384(private_key) => {
            let public_key = PublicKey::from_sec1_bytes(encoded_point.as_ref())?;
            let shared_secret = private_key.diffie_hellman(&public_key);
            Ok(SharedSecrets::NistP384(shared_secret))
        }
    }
}

pub fn encrypt() {}

pub fn decrypt() {}
