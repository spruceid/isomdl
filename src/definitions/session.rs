use super::helpers::Tag24;
use super::DeviceEngagement;
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
    sec1::FromEncodedPoint, PublicKey,
};
use hkdf::Hkdf;
use p256::NistP256;
use p384::NistP384;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Borrow;

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;
pub type DeviceEngagementBytes = Tag24<DeviceEngagement>;
pub type SessionTranscriptBytes = Tag24<SessionTranscript>;
pub type NfcHandover = (ByteStr, Option<ByteStr>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEstablishment {
    pub e_reader_key: EReaderKeyBytes,
    pub data: ByteStr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub data: Option<ByteStr>,
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

// TODO: Make this function cryptographically secure.
pub fn create_p256_ephemeral_keys() -> Result<(p256::SecretKey, CoseKey), Error> {
    let private_key = p256::SecretKey::random(&mut OsRng);

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
    e_device_key_priv: &p256::NonZeroScalar,
) -> Result<SharedSecret<NistP256>> {
    let encoded_point: EncodedPoint<NistP256> = EncodedPoint::<NistP256>::try_from(cose_key)?;
    let public_key_opt = p256::PublicKey::from_encoded_point(&encoded_point);
    if public_key_opt.is_none().into() {
        return Err(anyhow::anyhow!(
            "reader's public key could not be constructed"
        ));
    }
    let public_key = public_key_opt.unwrap();
    let shared_secret = p256::ecdh::diffie_hellman(e_device_key_priv, public_key.as_affine());
    Ok(shared_secret)
}

pub fn derive_session_key(
    shared_secret: &SharedSecret<NistP256>,
    session_transcript: &Tag24<SessionTranscript>,
    reader: bool,
) -> GenericArray<u8, U32> {
    // TODO: Handle error.
    let salt = Sha256::digest(serde_cbor::to_vec(session_transcript).unwrap());
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

    okm.into()
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
    use crate::definitions::device_engagement::Security;

    #[test]
    fn key_generation() {
        //todo fully test the exchange of keys and the resulting session keys e2e
        create_p256_ephemeral_keys(0).expect("failed to generate keys");
    }

    #[test]
    fn test_encryption_decryption() {
        let reader_keys = create_p256_ephemeral_keys(0).expect("failed to generate reader keys");
        let device_keys = create_p256_ephemeral_keys(1).expect("failed to generate device keys");
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

    #[test]
    fn debug() {
        let dk_hex = "c1917a1579949a042f1ba9fc53a2df9b1bc47adf31c10f813ed75702d1c1f136";
        let dk_bytes = hex::decode(dk_hex).unwrap();
        let device_key = p256::SecretKey::from_be_bytes(&dk_bytes).unwrap();
        let nzs: p256::NonZeroScalar = device_key.into();
        let se_hex = "a26a655265616465724b6579d818584ba40102200121582060e3392385041f51403051f2415531cb5".to_string()
            + "6dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c44"
            + "0c339bb0f7b67beccdfa64646174615902df52ada2acbeb6c390f2ca0bc659b484678eb94dd450743"
            + "86aadece23777b44606e42e2846bc2e2ee3c1e867b1d1685e41354a021abb0fda36f09cf5d5c51b56"
            + "1d3be41c9347ae71cf2b49de9dec7b44046ab02247931b210c9157840c1514a6027b08810716adf61"
            + "966344979314ac3ae9f40e66e015c1254a684108bd093e8772ec333fb663fd6803af02ea10bdbe83a"
            + "999f75b55a180f872139fb57ac04acd58ca15eca150cde1c3b849401188b7a30ce887dd7b71b12eda"
            + "2fc6ec6e5235a6c9498351fcd301f2292a4ebba7555285cee84ead96ef1677b0af8239f6a7a52af4b"
            + "8809b1d52ab21a162ca31ade21c57bd1d9970a2832aac41c7d52d1c4fee4ee64030a218df51363be7"
            + "01792fa6c515c489bd39dcad6fba48f1d6eb19e9c769531a3bf9998a32c01841305f23844ca3db6a1"
            + "ff0d0d917343d62fc72ad58eab01a3198116f19606609f94e35eacb78d23c59c67852a361915fe878"
            + "48cdba5630c99fab71aeff72d131cf442654f7708ec48216416f2d996cf6cf91012b771b88907b1d1"
            + "629dfa794343e653c31207482e2f6621cd4b5dcf3b3c328625c33fe98be99c5f264a264315be41baf"
            + "dc726f8bcde5920de0a71884d860af44c1ff1b3d78b2e8d720d85dae53fea2b3fa1806162a4be02d0"
            + "39567c5eb2419c2ad879af48fcb7df55ca94f1b00f62187fa2329c8227aae0130ec052ca3e2102e57"
            + "e72911b328cfdcfbaaf6b9364660f613415382644c30c0bd4e222c5cf94ba5a73679c53d5ced95ca5"
            + "0787c2289a0c17358393c1e0f2272361002fb9b160606888a59ef7a2c389f68b7cb424572db026b17"
            + "cf2bdcafcb67c8292d92b50050356900a62a82b16f854759052b00f0f4673a46229f43257e8e83254"
            + "01b3fecc8c6d2258baf7f7c2fbbafab3a1b6aded4eceac1eafd5b61118df93bc0a622b03504fde47c"
            + "ebb224e983db12677e316c22aae042d6ce4adae0d8b0f40437b8e1afa0859c9501beb63974496859a"
            + "60f11069b1965b4ffac5779a96191f89eac7caa688b9e67c";
        let se_bytes = hex::decode(se_hex).unwrap();
        let se: SessionEstablishment = serde_cbor::from_slice(&se_bytes).unwrap();
        let reader_key = se.e_reader_key;
        let encrypted = se.data;

        let ss = get_shared_secret2(reader_key.as_ref().clone(), &nzs).unwrap();
        let ss_hexstr = hex::encode(ss.raw_secret_bytes());
        let expected_ss = "6423502f843d8cda01fbd9fa46cb397534a740ab1ec3d1076fbcb12e1dca2589";
        assert_eq!(ss_hexstr, expected_ss);

        let st_hex = "d81859024183d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa5".to_string()
            + "9943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338"
            + "237a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f"
            + "2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796"
            + "f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301013001046d646f631a200"
            + "c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37"
            + "282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746"
            + "d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e"
            + "8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6"
            + "aa672fc60a557aa32fc6758cd91022548721591020263720102110204616301013000110206616301"
            + "036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e626c7565746f6"
            + "f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4823a"
            + "1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2"
            + "f766e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e853"
            + "3e5f00298cfccbc35e700a6b020414";
        let st_bytes = hex::decode(st_hex).unwrap();
        let st: Tag24<SessionTranscript> = serde_cbor::from_slice(&st_bytes).unwrap();

        let sk = derive_session_key(&ss, &st, true);
        let sk_hexstr = hex::encode(&sk);
        let expected_sk = "58d277d8719e62a1561d248f403f477e9e6c37bf5d5fc5126f8f4c727c22dfc9";
        assert_eq!(sk_hexstr, expected_sk);

        let plaintext = decrypt_reader_data(&sk, encrypted.as_ref(), &mut 0).unwrap();
        let dr: crate::definitions::device_request::DeviceRequest =
            serde_cbor::from_slice(&plaintext).unwrap();
        println!("{:?}", dr);
    }
}
