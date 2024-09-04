//! This module contains the definitions and functions related to session establishment and management.
//!
//! The [get_initialization_vector] function generates an initialization vector for encryption/decryption
//! based on a message count and a flag indicating whether the vector is for the reader or the device.

use aes::cipher::{generic_array::GenericArray, typenum::U32};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce, // Or `Aes128Gcm`
};
use anyhow::Result;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use ecdsa::EncodedPoint;
use elliptic_curve::{
    ecdh::EphemeralSecret, ecdh::SharedSecret, generic_array::sequence::Concat,
    sec1::FromEncodedPoint,
};
use hkdf::Hkdf;
use isomdl_macros::FieldsNames;
use p256::NistP256;
use p384::NistP384;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::cbor::CborValue;
use crate::definitions::device_engagement::EReaderKeyBytes;
use crate::definitions::device_key::cose_key::EC2Y;
use crate::definitions::device_key::CoseKey;
use crate::definitions::device_key::EC2Curve;
use crate::definitions::helpers::bytestr::ByteStr;
use crate::definitions::session::EncodedPoints::{Ep256, Ep384};

use super::helpers::Tag24;
use super::DeviceEngagement;

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;
pub type DeviceEngagementBytes = Tag24<DeviceEngagement>;
pub type SessionTranscriptBytes = Tag24<SessionTranscript180135>;
pub type NfcHandover = (ByteStr, Option<ByteStr>);

/// Represents the establishment of a session.
#[derive(Debug, Clone, FieldsNames, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[isomdl(rename_all = "camelCase")]
pub struct SessionEstablishment {
    /// The EReader key used for a session establishment.
    pub e_reader_key: EReaderKeyBytes,

    /// The data associated with the session establishment.
    pub data: ByteStr,
}

impl CborSerializable for SessionEstablishment {}
impl AsCborValue for SessionEstablishment {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "doc_requests is missing".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(SessionEstablishment {
            e_reader_key: EReaderKeyBytes::from_cbor_value(
                map.remove(&SessionEstablishment::fn_e_reader_key().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, "e_reader_key is missing".to_string()),
                    ))?
                    .into(),
            )?,
            data: map
                .remove(&SessionEstablishment::fn_e_reader_key().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "data is missing".to_string()),
                ))?
                .try_into()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "data is not a byte string".to_string(),
                    ))
                })?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let map = vec![
            (
                Value::Text(SessionEstablishment::fn_e_reader_key().to_string()),
                self.e_reader_key.to_cbor_value()?,
            ),
            (
                Value::Text(SessionEstablishment::fn_data().to_string()),
                self.data.into(),
            ),
        ];
        Ok(Value::Map(map))
    }
}

/// Represents session data.
#[derive(Debug, Clone, FieldsNames)]
pub struct SessionData {
    /// An optional [ByteStr] that represents the data associated with the session.  
    /// The field is skipped during serialization if it is [None].
    #[isomdl(skip_serializing_if = "Option::is_none")]
    pub data: Option<ByteStr>,

    /// An optional [Status] that represents the status of the session.  
    /// Similarly, the field is skipped during serialization if it is [None].
    #[isomdl(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

impl CborSerializable for SessionData {}
impl AsCborValue for SessionData {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "SessionData is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(SessionData {
            data: map
                .remove(&SessionData::fn_data().into())
                .map(|v| {
                    v.try_into().map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "data is not a byte string".to_string(),
                        ))
                    })
                })
                .transpose()?,
            status: None,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![];
        if let Some(data) = self.data {
            map.push((Value::Text(SessionData::fn_data().to_string()), data.into()));
        }
        if let Some(status) = self.status {
            map.push((
                Value::Text(SessionData::fn_status().to_string()),
                Value::Integer((status as u64).into()),
            ));
        }
        Ok(Value::Map(map))
    }
}

#[derive(Clone, Debug)]
pub enum Status {
    SessionEncryptionError = 10,
    CborDecodingError = 11,
    SessionTermination = 20,
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

pub trait SessionTranscript:
    Serialize + for<'a> Deserialize<'a> + CborSerializable + AsCborValue
{
}

/// Represents the device engagement bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTranscript180135(
    pub DeviceEngagementBytes,
    pub Tag24<EReaderKey>,
    pub Handover,
);

impl CborSerializable for SessionTranscript180135 {}
impl AsCborValue for SessionTranscript180135 {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut arr = value
            .into_array()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "not an array".to_string(),
                ))
            })?
            .into_iter()
            .map(|v| v.into())
            .collect::<Vec<CborValue>>();
        if arr.len() != 3 {
            return Err(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "wrong number of items".to_string()),
            ));
        }
        Ok(SessionTranscript180135(
            DeviceEngagementBytes::from_cbor_value(arr.remove(0).try_into().map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "device_engagement is not a tag 24".to_string(),
                ))
            })?)?,
            Tag24::<EReaderKey>::from_cbor_value(arr.remove(0).try_into().map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "e_reader_key is not a tag 24".to_string(),
                ))
            })?)?,
            Handover::from_cbor_value(arr.remove(0).try_into().map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "handover is not a tag 24".to_string(),
                ))
            })?)?,
        ))
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Array(vec![
            self.0.to_cbor_value()?,
            self.1.to_cbor_value()?,
            self.2.to_cbor_value()?,
        ]))
    }
}

impl SessionTranscript for SessionTranscript180135 {}

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
#[serde(untagged)]
pub enum Handover {
    QR,
    NFC(ByteStr, Option<ByteStr>),
    OID4VP(String, String),
}

impl CborSerializable for Handover {}
impl AsCborValue for Handover {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        match value {
            Value::Null => Ok(Handover::QR),
            Value::Array(_) => {
                let mut arr = value.into_array().map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "not an array".to_string(),
                    ))
                })?;
                match arr.len() {
                    1 => {
                        let v = arr.remove(0);
                        let cbor: CborValue = v.into();
                        Ok(Handover::NFC(
                            cbor.try_into().map_err(|_| {
                                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                    None,
                                    "NFC is not a ByteStr".to_string(),
                                ))
                            })?,
                            None,
                        ))
                    }
                    2 => {
                        let v1 = arr.remove(0);
                        let v2 = arr.remove(0);
                        match (v1, v2) {
                            (Value::Bytes(b1), Value::Bytes(b2)) => {
                                Ok(Handover::NFC(ByteStr::from(b1), Some(ByteStr::from(b2))))
                            }
                            (Value::Bytes(b1), Value::Null) => {
                                Ok(Handover::NFC(ByteStr::from(b1), None))
                            }
                            (Value::Text(s1), Value::Text(s2)) => Ok(Handover::OID4VP(s1, s2)),
                            _ => Err(coset::CoseError::DecodeFailed(
                                ciborium::de::Error::Semantic(None, "not a handover".to_string()),
                            )),
                        }
                    }
                    _ => Err(coset::CoseError::ExtraneousData),
                }
            }
            _ => Err(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "not a handover".to_string()),
            )),
        }
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(match self {
            Handover::QR => Value::Null,
            Handover::NFC(b, b2) => {
                let mut arr = vec![b.into()];
                if let Some(b2) = b2 {
                    arr.push(Value::Bytes(b2.into()));
                } else {
                    arr.push(Value::Null);
                }
                Value::Array(arr)
            }
            Handover::OID4VP(s, s2) => {
                let s: Value = s.into();
                let s2: Value = s2.into();
                Value::Array(vec![s, s2])
            }
        })
    }
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
    session_transcript: &SessionTranscriptBytes,
    reader: bool,
) -> Result<GenericArray<u8, U32>> {
    let salt = Sha256::digest(session_transcript.clone().to_vec()?);
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
    use crate::definitions::device_engagement::Security;
    use crate::definitions::device_request::DeviceRequest;

    use super::*;

    #[test]
    fn qr_handover() {
        // null
        let cbor = hex::decode("F6").expect("failed to decode hex");
        let handover = Handover::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR) {
            panic!("expected 'Handover::QR', received {handover:?}")
        } else {
            let roundtripped = handover
                .to_vec()
                .expect("failed to serialize handover as cbor");
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
        let handover = Handover::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR) {
            panic!("expected 'Handover::QR', received {handover:?}")
        } else {
            let roundtripped = handover
                .to_vec()
                .expect("failed to serialize handover as cbor");
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
        let handover = Handover::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR) {
            panic!("expected 'Handover::QR', received {handover:?}")
        } else {
            let roundtripped = handover
                .to_vec()
                .expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    fn nfc_static_handover() {
        // ['hello', null]
        let cbor = hex::decode("824568656C6C6FF6").expect("failed to decode hex");
        let handover = Handover::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::NFC(..)) {
            panic!("expected 'Handover::NFC(..)', received {handover:?}")
        } else {
            let roundtripped = handover
                .to_vec()
                .expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    fn nfc_negotiated_handover() {
        // ['hello', 'world']
        let cbor = hex::decode("824568656C6C6F45776F726C64").expect("failed to decode hex");
        let handover = Handover::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::NFC(..)) {
            panic!("expected 'Handover::NFC(..)', received {handover:?}")
        } else {
            let roundtripped = handover
                .to_vec()
                .expect("failed to serialize handover as cbor");
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
        let handover = Handover::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::OID4VP(..)) {
            panic!(
                "expected '{}', received {:?}",
                "Handover::OID4VP(..)", handover
            )
        } else {
            let roundtripped = handover
                .to_vec()
                .expect("failed to serialize handover as cbor");
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
        let session_establishment =
            SessionEstablishment::from_slice(&session_establishment_bytes).unwrap();

        let e_reader_key = session_establishment.e_reader_key;
        let encrypted_request = session_establishment.data;

        let shared_secret =
            get_shared_secret(e_reader_key.as_ref().clone(), &e_device_key_inner).unwrap();
        let shared_secret_hex = hex::encode(shared_secret.raw_secret_bytes());
        assert_eq!(shared_secret_hex, SHARED_SECRET);

        let session_transcript_bytes = hex::decode(SESSION_TRANSCRIPT).unwrap();
        let session_transcript =
            SessionTranscriptBytes::from_slice(&session_transcript_bytes).unwrap();

        let session_key = derive_session_key(&shared_secret, &session_transcript, true).unwrap();
        let session_key_hex = hex::encode(session_key);
        assert_eq!(session_key_hex, READER_SESSION_KEY);

        let plaintext =
            decrypt_reader_data(&session_key, encrypted_request.as_ref(), &mut 0).unwrap();
        let _device_request = DeviceRequest::from_slice(&plaintext).unwrap();
    }
}
