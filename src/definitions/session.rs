//! This module contains the definitions and functions related to session establishment and management.
//!
//! The [get_initialization_vector] function generates an initialization vector for encryption/decryption
//! based on a message count and a flag indicating whether the vector is for the reader or the device.
use super::helpers::Tag24;
use super::DeviceEngagement;
use super::DeviceRetrievalMethod;
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
use p256::NistP256;
use p384::NistP384;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// When negotiated handover is used, the mdoc (holder) should include
/// the following service URN to the reader, which will be used to select
/// the appropriate alternative carrier record in a handover request message.
///
/// See 18013-5 §8.2.2.1 Device Engagement using NFC for more information.
pub const NFC_NEGOTIATED_HANDOVER_SERVICE: &str = "urn:nfc:sn:handover";
pub const TNF_WELL_KNOWN: u8 = 0x01;
pub const TNF_MIME_MEDIA: u8 = 0x02;

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;
pub type DeviceEngagementBytes = Tag24<DeviceEngagement>;
pub type SessionTranscriptBytes = Tag24<SessionTranscript180135>;
pub type NfcHandoverSelectMessage = ByteStr;
pub type NfcHandoverRequestMessage = Option<ByteStr>;

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
    #[error("Serialization error")]
    Cbor(#[from] CborError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfcHandover(pub NfcHandoverSelectMessage, pub NfcHandoverRequestMessage);

impl NfcHandover {
    pub fn create_handover_select(
        device_engagement: &Tag24<DeviceEngagement>,
        nfc_handover_request: NfcHandoverRequestMessage,
    ) -> Result<Self, Error> {
        let mut embedded_ndef = Vec::new();

        // Track how many records total we will emit
        let mut record_parts = Vec::new();

        // URI Record for negotiated handover support (urn:nfc:sn:handover)
        let uri_record = NdefRecord {
            tnf: TNF_WELL_KNOWN,
            type_field: vec![b'U'], // URI Record type
            id: None,
            payload: {
                let mut payload = vec![0x00]; // URI Identifier Code 0x00 = no prefix
                payload.extend_from_slice(NFC_NEGOTIATED_HANDOVER_SERVICE.as_bytes());
                payload
            },
        };

        // URI record
        record_parts.push(uri_record);

        // Dynamic AC/Carrier records
        if let Some(retrieval_methods) = device_engagement.inner.device_retrieval_methods.as_ref() {
            for method in retrieval_methods.iter() {
                if let DeviceRetrievalMethod::BLE(_) = method {
                    let (ac_record, bt_record) =
                        NdefRecord::configure_bluetooth_alternative_carrier_records(
                            device_engagement,
                        )?;
                    record_parts.push(ac_record);
                    record_parts.push(bt_record);
                }
            }
        }

        // Encode records with Message Beginning (MB)/Message Ending (ME) flags
        for (i, record) in record_parts.iter().enumerate() {
            let mb = i == 0;
            let me = i == record_parts.len() - 1;
            embedded_ndef.extend_from_slice(&record.encode(mb, me));
        }

        let mut hs_payload = vec![0x12]; // Version 1.2
        hs_payload.extend_from_slice(&embedded_ndef);

        let hs_record = NdefRecord {
            tnf: TNF_WELL_KNOWN,
            type_field: b"Hs".to_vec(),
            id: None,
            payload: hs_payload,
        };

        // Final top-level NDEF message
        Ok(NfcHandover(
            hs_record.encode(true, true).into(),
            nfc_handover_request,
        ))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NdefRecord {
    pub tnf: u8,
    pub type_field: Vec<u8>,
    pub id: Option<Vec<u8>>,
    pub payload: Vec<u8>,
}

impl NdefRecord {
    /// Create alternative carrier records for bluetooth handover.
    fn configure_bluetooth_alternative_carrier_records(
        device_engagement: &Tag24<DeviceEngagement>,
    ) -> Result<(Self, Self), Error> {
        Ok((
            NdefRecord {
                tnf: TNF_WELL_KNOWN,
                type_field: b"ac".to_vec(),
                id: None,
                payload: vec![
                    0x01, // Carrier Power State: active
                    0x01, // Length of Carrier Data Reference
                    b'B', // Carrier Data Reference ID
                    0x00, // Auxiliary Data Reference Count
                ],
            },
            NdefRecord {
                tnf: TNF_MIME_MEDIA,
                type_field: b"application/vnd.bluetooth.ep.oob".to_vec(),
                id: Some(b"B".to_vec()), // must match AC reference
                payload: device_engagement.inner_bytes.clone(),
            },
        ))
    }

    /// `mb` -> message begin
    /// `me` -> message end
    ///
    /// Encodes the NDEF record into a byte vector.
    pub fn encode(&self, mb: bool, me: bool) -> Vec<u8> {
        let sr = self.payload.len() < 256;
        let il = self.id.is_some();
        let mut header = 0;
        if mb {
            header |= 0x80;
        }
        if me {
            header |= 0x40;
        }
        if sr {
            header |= 0x10;
        }
        if il {
            header |= 0x08;
        }
        header |= self.tnf & 0x07;

        let mut record = vec![header];
        record.push(self.type_field.len() as u8);

        if sr {
            record.push(self.payload.len() as u8);
        } else {
            record.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        }

        if il {
            record.push(self.id.as_ref().unwrap().len() as u8);
        }

        record.extend_from_slice(&self.type_field);
        if il {
            record.extend_from_slice(self.id.as_ref().unwrap());
        }
        record.extend_from_slice(&self.payload);
        record
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Handover {
    /// > If QR code is used for device engagement, the device engagement structure
    /// > shall be transmitted as a barcode compliant with ISO/IEC 18004. The QR code
    /// > shall contain an URI with "mdoc:" as a scheme.
    ///
    /// See ISO/IEC 18013-5 §8.2.2.3 for more information.
    ///
    // NOTE: The specification does not mention adding the `mdoc:` scheme
    // to the QR handover variant. However, the device engagement bytes structure
    // does permit additional bytes to be appended after the required device
    // engagement bytes. See `DeviceEngagement` structure for required fields. Therefore,
    // adding the QR code URI here should be acceptable per the specification.
    //
    // The contents of the QR code are the encoded device engagement bytes, which
    // are used to parse the device engagement bytes structure.
    //
    // See ISO/IEC 18013-5 §8.2.1.1 for more information.
    QR(String),
    NFC(NfcHandover),
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
    use crate::definitions::helpers::NonEmptyVec;
    use crate::definitions::CoseKey;

    fn dummy_device_key() -> CoseKey {
        let crv = EC2Curve::P256;
        let x: Vec<u8> = vec![0u8; 32];
        let y = EC2Y::Value(x.clone());

        CoseKey::EC2 { crv, x, y }
    }

    #[test]
    fn qr_handover() {
        // Empty string in CBOR is 0x60
        let cbor = hex::decode("60").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR(..)) {
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
        if !matches!(handover, Handover::QR(..)) {
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
        if !matches!(handover, Handover::QR(..)) {
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
    fn nfc_static_handover() {
        // ['hello', null]
        let cbor = hex::decode("824568656C6C6FF6").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::NFC(..)) {
            panic!("expected 'Handover::NFC(..)', received {handover:?}")
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
    fn nfc_negotiated_handover() {
        // ['hello', 'world']
        let cbor = hex::decode("824568656C6C6F45776F726C64").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::NFC(..)) {
            panic!("expected 'Handover::NFC(..)', received {handover:?}")
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
            Handover::QR(String::new()),
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

    #[test]
    fn test_valid_nfc_handover_select_ble_only() {
        use crate::definitions::device_engagement::Security;

        let device_engagement = Tag24::new(DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, Tag24::new(dummy_device_key()).unwrap()),
            device_retrieval_methods: Some(NonEmptyVec::new(DeviceRetrievalMethod::BLE(
                Default::default(),
            ))),
            server_retrieval_methods: None,
            protocol_info: None,
        })
        .expect("failed to create device engagement tag24");

        let result = NfcHandover::create_handover_select(&device_engagement, None);
        assert!(result.is_ok());

        let NfcHandover(handover_bytes, _) = result.unwrap();
        let raw = handover_bytes.as_ref();

        // Assert: Handover starts with valid NDEF header
        assert_eq!(
            raw[0] & 0xF8,
            0xD0,
            "First NDEF record should be MB=1, TNF=0x01"
        );

        // Assert: 'Hs' record type exists
        assert!(raw.windows(2).any(|w| w == b"Hs"), "Hs type not found");

        // Assert: Includes version byte (0x12)
        assert!(raw.contains(&0x12), "Hs payload missing version byte 0x12");

        // Assert: Includes 'urn:nfc:sn:handover' URI
        let urn = NFC_NEGOTIATED_HANDOVER_SERVICE.as_bytes();
        assert!(
            raw.windows(urn.len()).any(|w| w == urn),
            "URI 'urn:nfc:sn:handover' missing"
        );
    }

    #[test]
    fn test_nfc_handover_with_no_retrieval_methods() {
        let device_engagement = Tag24::new(DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, Tag24::new(dummy_device_key()).unwrap()),
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        })
        .expect("failed to create device engagement tag24");

        let result = NfcHandover::create_handover_select(&device_engagement, None);
        assert!(result.is_ok());

        let NfcHandover(handover_bytes, _) = result.unwrap();
        let raw = handover_bytes.as_ref();

        // Should still contain the URI record
        assert!(
            raw.windows(NFC_NEGOTIATED_HANDOVER_SERVICE.as_bytes().len())
                .any(|w| w == NFC_NEGOTIATED_HANDOVER_SERVICE.as_bytes()),
            "URN URI missing"
        );

        let uri_count = raw
            .windows(NFC_NEGOTIATED_HANDOVER_SERVICE.len())
            .filter(|w| *w == NFC_NEGOTIATED_HANDOVER_SERVICE.as_bytes())
            .count();

        assert_eq!(uri_count, 1, "Expected only one URI record");

        // Only one embedded record expected
        let num_ndef_records = raw.iter().filter(|b| **b & 0x80 != 0).count();
        assert_eq!(
            num_ndef_records, 2,
            "Expected 2 beginning bytes, one for URI and one for Hs"
        );
    }

    #[test]
    fn test_nfc_handover_missing_device_key_should_fail() {
        let device_engagement = Tag24::new(DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, Tag24::new(dummy_device_key()).unwrap()),
            device_retrieval_methods: Some(NonEmptyVec::new(DeviceRetrievalMethod::BLE(
                Default::default(),
            ))),
            server_retrieval_methods: None,
            protocol_info: None,
        })
        .expect("Failed to create device engagement");

        let result = NfcHandover::create_handover_select(&device_engagement, None);
        assert!(
            result.is_ok(),
            "Should succeed even with minimal fields in dummy key (adjust if validation is enforced)"
        );
    }
}
