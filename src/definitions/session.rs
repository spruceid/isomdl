use crate::definitions::device_engagement::EReaderKeyBytes;
use crate::definitions::device_key::CoseKey;
use crate::definitions::helpers::bytestr::ByteStr;
use crate::definitions::session::EncodedPoints::{Ep256, Ep384};
use crate::definitions::session::EphemeralSecrets::{Eph256, Eph384};
use anyhow::Result;
use ecdsa::EncodedPoint;
use elliptic_curve::{ecdh::EphemeralSecret, ecdh::SharedSecret, PublicKey};
use p256::NistP256;
use p384::NistP384;
use rand_core::OsRng; // requires 'getrandom' feature
use serde::{Deserialize, Serialize};

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;
pub type DeviceEngagementBytes = Vec<u8>;
pub type SessionTranscript = (DeviceEngagementBytes, EReaderKeyBytes, Handover);
pub type NfcHandover = (String, Option<String>);

#[derive(Debug, Clone)]
pub struct SessionEstablishment {
    e_reader_key: EReaderKey,
    data: ByteStr,
}

#[derive(Debug, Clone)]
pub struct SessionData {
    data: ByteStr,
    status: u64,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Curve not supported for DH exchange")]
    UnsupportedCurve,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Handover {
    QRHANDOVER,
    NFCHANDOVER,
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
    //return  EDeviceKey.Priv, EDeviceKey.Pub and a cipher suite identifier
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

pub fn derive_shared_secret(
    encoded_point: Vec<u8>,
    e_device_key_priv: EphemeralSecrets,
) -> Result<SharedSecrets> {
    match e_device_key_priv {
        Eph256(private_key) => {
            let public_key = PublicKey::from_sec1_bytes(encoded_point.as_ref())?;
            let shared_secret = private_key.diffie_hellman(&public_key);

            Ok(SharedSecrets::Ss256(shared_secret))
        }
        Eph384(private_key) => {
            let public_key = PublicKey::from_sec1_bytes(encoded_point.as_ref())?;
            let shared_secret = private_key.diffie_hellman(&public_key);
            Ok(SharedSecrets::Ss384(shared_secret))
        }
    }
}

pub fn encrypt() {}

pub fn decrypt() {}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn key_generation() {
        let key_pair = generate_ephemeral_keys(Curves::P256);
    }
}
