use crate::x5chain::{self, X5Chain};
use anyhow::Result;
use aws_nitro_enclaves_cose::crypto::{
    Hash, MessageDigest, Openssl, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey,
};
use aws_nitro_enclaves_cose::error::CoseError;
use aws_nitro_enclaves_cose::header_map::HeaderMap;
use aws_nitro_enclaves_cose::{sign, CoseSign1};
use cddl::{parser::cddl_from_str, validate_json_from_str};
use chrono::{DateTime, FixedOffset, Offset, Utc};
use der::Writer;
use der::{Document, Encode};
use ecdsa::signature::digest::Key;
use ecdsa::{signature::Signature, SigningKey};
use openssl::ec::EcKey;
use openssl::pkey::{Id, PKey, Private, Public};
use p256::{AffinePoint, NistP256, PublicKey};
use rand::Rng;
use rand_core::OsRng;
use ring::digest::{Context, Digest, SHA256, Algorithm as RingDigestAlgorithm};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_cbor::{self, value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::{HashMap, HashSet};
use std::str::Bytes;

const ALG: i128 = 1;
const X5CHAIN: i128 = 33;
const PEM_FILE: &'static str = include_str!("../test.pem");

type Namespaces = HashMap<String, HashMap<String, CborValue>>;
type DigestIds = HashMap<DigestID, Vec<u8>>;
type IssuerSignedItemBytes = [u8];
type DigestID = u64;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Mdoc {
    doc_type: String,
    namespaces: Namespaces,
    mobile_security_object: Mso,
    issuer_auth: Option<CoseSign1>,
}

pub struct PreparationMdoc {
    doc_type: String,
    namespaces: Namespaces,
    mobile_security_object: Mso,
    x5chain: X5Chain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mso {
    version: String,
    digest_algorithm: DigestAlgorithm,
    value_digests: HashMap<String, HashMap<DigestID, Vec<u8>>>,
    device_key_info: DeviceKeyInfo,
    doc_type: String,
    validity_info: ValidityInfo,
}

pub struct IssuerSigned {
    namespaces: IssuerNamespace,
    issuer_auth: CoseSign1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerSignedItem {
    digest_id: u64,
    random: [u8; 16],
    element_identifier: String,
    element_value: CborValue,
}

pub struct IssuerNamespace {
    namespace: HashMap<String, IssuerSignedItem>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MobileSecurityObjectBytes {
    data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceKeyInfo {
    device_key: CoseKey,
    key_authorization: Option<KeyAuthorization>,
}

pub trait Signer {
    fn alg() {}

    fn sign() {}
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeyAuthorization {
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_namespaces: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_data_elements: Option<HashMap<String, Vec<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
// To Do: change datetimes to more specific types for mDL
pub struct ValidityInfo {
    signed: DateTime<Utc>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    expected_update: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoseKey {
    kty: KeyType,
    alg: SignatureAlgorithm,
}

#[derive(Clone, Debug, Copy, Deserialize, Serialize)]
pub enum DigestAlgorithm {
    SHA256,
    SHA384,
    SHA512,
}

impl PreparationMdoc {
    fn complete<T: SigningPrivateKey + SigningPublicKey + DeviceKeyInfoTrait>(
        self,
        signer: T,
    ) -> Mdoc {
        //encode mso to cbor
        let mobile_security_object_bytes = to_cbor(self.mobile_security_object.clone());

        //headermap should contain alg header and x5chain header
        let cose_key = signer.get_cose_key().alg;
        let mut alg_header_map: HeaderMap = signer.get_alg().into();
        let mut buf: Vec<u8> = vec![];

        let x5chain_cbor = self.x5chain.into_cbor();
        let mut cert_header_map = HeaderMap::new();
        cert_header_map.insert(serde_cbor::Value::Integer(X5CHAIN), x5chain_cbor);

        let cose_sign1 = sign::CoseSign1::new_with_protected::<Openssl>(
            &mobile_security_object_bytes.unwrap(),
            &alg_header_map,
            &cert_header_map,
            &signer,
        );

        let mdoc = Mdoc {
            doc_type: "org.iso.18013.5.1".to_string(),
            namespaces: self.namespaces,
            mobile_security_object: self.mobile_security_object,
            issuer_auth: Some(cose_sign1.unwrap()),
        };

        mdoc
    }
}

impl Mdoc {
    pub fn prepare_mdoc<T: SigningPrivateKey + SigningPublicKey + DeviceKeyInfoTrait>(
        doc_type: String,
        namespaces: Namespaces,
        issuerx5chain: X5Chain,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        signer: T,
        key_authorization: Option<KeyAuthorization>,
    ) -> Result<PreparationMdoc> {
        let device_key_info = DeviceKeyInfo {
            device_key: signer.get_cose_key(),
            key_authorization: key_authorization,
        };

        let value_digest =
            Mdoc::digest_namespaces(&namespaces, digest_algorithm)?;

        let mso = Mso {
            version: "1.0".to_string(),
            digest_algorithm,
            value_digests: value_digest,
            device_key_info: device_key_info,
            doc_type: doc_type.clone(),
            validity_info: validity_info,
        };

        let preparation_mdoc = PreparationMdoc {
            doc_type,
            namespaces,
            mobile_security_object: mso,
            x5chain: issuerx5chain,
        };

        Ok(preparation_mdoc)
    }

    pub fn digest_namespaces(
        namespaces: &Namespaces,
        digest_algorithm: DigestAlgorithm,
    ) -> Result<HashMap<String, HashMap<DigestID, Vec<u8>>>> {
        fn digest_namespace(
            elements: &HashMap<String, CborValue>,
            digest_algorithm: DigestAlgorithm
        ) -> Result<HashMap<DigestID, Vec<u8>>> {
            let mut used_ids: HashSet<u64> = HashSet::new();
            elements.iter()
                .map(|(key, value)| {
                    let mut digest_id;
                    loop {
                        digest_id = rand::thread_rng().gen();
                        if used_ids.insert(digest_id) {
                            break;
                        }
                    }
                    let issuer_signed_item = IssuerSignedItem {
                        digest_id,
                        random: rand::thread_rng().gen::<[u8; 16]>(),
                        element_identifier: key.to_string(),
                        element_value: value.clone(),
                    };
                    let issuer_signed_item_bytes = serde_cbor::to_vec(&issuer_signed_item)?;
                    let ring_alg = match digest_algorithm {
                        DigestAlgorithm::SHA256 => &ring::digest::SHA256,
                        DigestAlgorithm::SHA384 => &ring::digest::SHA384,
                        DigestAlgorithm::SHA512 => &ring::digest::SHA512,
                    };
                    let digest = ring::digest::digest(ring_alg, &issuer_signed_item_bytes);
                    return Ok((digest_id, digest.as_ref().to_vec()))
                })
                .collect()
        }

        namespaces.iter()
            .map(|(name, elements)| Ok((name.clone(), digest_namespace(elements, digest_algorithm)?)))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct PrivateKey {
    pkey: SigningKey<NistP256>,
}

impl SigningPrivateKey for PrivateKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        use ecdsa::signature::Signer;
        let signature = self.pkey.sign(data);
        let result = signature.as_bytes();
        Ok(result.to_vec())
    }
}

impl SigningPublicKey for PrivateKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        let sig = SignatureAlgorithm::ES256;
        let msg = MessageDigest::Sha256;
        Ok((sig, msg))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        Ok(true)
    }
}

pub trait DeviceKeyInfoTrait {
    fn get_alg(&self) -> SignatureAlgorithm;
    fn get_kty(&self) -> KeyType;
    fn get_cose_key(&self) -> CoseKey;
}

impl DeviceKeyInfoTrait for PrivateKey {
    fn get_cose_key(&self) -> CoseKey {
        let cose_key = CoseKey {
            kty: KeyType::EC,
            alg: SignatureAlgorithm::ES256,
        };
        cose_key
    }
    fn get_alg(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ES256
    }

    fn get_kty(&self) -> KeyType {
        KeyType::EC
    }
}

#[derive(Clone, Debug, Serialize_repr, Deserialize_repr)]
#[repr(i64)]
pub enum KeyType {
    EC,
}

pub fn generate_keys() -> (PublicKey, SigningKey<NistP256>) {
    let affine_point = AffinePoint::GENERATOR;
    let public_key = PublicKey::try_from(affine_point).unwrap();
    let signing_key = SigningKey::<NistP256>::random(&mut OsRng); // Serialize with `::to_bytes()`

    (public_key, signing_key)
}

pub fn to_cbor<T: Serialize>(input: T) -> Result<Vec<u8>, serde_cbor::Error> {
    let cbor_mdoc = serde_cbor::to_vec(&input);
    cbor_mdoc
}

pub fn from_cbor(mso_bytes: Vec<u8>) -> Result<Mso, serde_cbor::Error> {
    let mso: Result<Mso, serde_cbor::Error> = serde_cbor::from_slice(&mso_bytes);
    mso
}

pub fn x5chain_to_cbor(chain: &[Document]) -> CborValue {
    let cbor_chain: Vec<CborValue> = chain
        .iter()
        .map(|doc| doc.as_bytes().to_vec())
        .map(CborValue::Bytes)
        .collect();
    CborValue::Array(cbor_chain)
}

pub fn create_issuer_signed_item(key: String, value: String) {}

/// TODO
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalBstr {}

/// TODO: fix (de)serialize
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tstr {
    tstr: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tdate {
    tdate: DateTime<FixedOffset>,
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::mdoc;
    use p256::NistP256;
    use serde_cbor::value;

    #[test]
    pub fn issue_credential_test() {
        let mut info_mdoc = load_mock_data();
        let namespaces = info_mdoc.namespaces;
        let device_key_info = info_mdoc.mobile_security_object.device_key_info.clone();
        let doc_type = info_mdoc.doc_type.clone();
        let validity_info = info_mdoc.mobile_security_object.validity_info.clone();
        let signing_alg = info_mdoc.mobile_security_object.digest_algorithm.clone();

        let keys = generate_keys(); //move out of mdoc?
        let sig_key = keys.1.clone();
        let signer = PrivateKey { pkey: sig_key };

        //parse x509 from pem
        static IGCA_PEM: &str = "./test.pem";
        let x5chain = std::fs::read(IGCA_PEM).expect("Could not read file");
        let issuerx5chain = x5chain::X5Chain::from(vec![x5chain]);
        let key_authorization = device_key_info.key_authorization;

        let digest_algorithm = "SHA256".to_string();

        let mut mdoc = load_mock_data();

        let preparation_mdoc = mdoc.prepare_mdoc(
            doc_type,
            namespaces,
            issuerx5chain,
            validity_info,
            digest_algorithm,
            signer.clone(),
            key_authorization,
        );

        let issued_credential = preparation_mdoc.complete(signer);

        println!("issued_credential {:?}", issued_credential);
    }

    #[test]
    pub fn cbor_encode_mdoc() {}

    #[test]
    pub fn generate_key_test() {
        let mdoc: Mdoc = load_mock_data();
        let keys = generate_keys();
        println!("keys: {:?}", keys);
    }

    #[test]
    pub fn test_digest_namespaces() {
        //set up some data to enter into an mdoc
        let mdoc = load_mock_data();
        let namespaces = mdoc.namespaces.clone();
        let device_key_info = mdoc.mobile_security_object.device_key_info.clone();
        let digest_algorithm = "SHA256".to_string();

        let value_digest = mdoc.digest_namespaces(&namespaces, &device_key_info, digest_algorithm);
        println!("value_digest {:?}", value_digest);
        //asserteq
    }

    pub fn load_mock_data() -> Mdoc {
        let mut namespaces: Namespaces = HashMap::<String, HashMap<String, String>>::new();

        let mut org_iso_1801351_namespace = HashMap::<String, String>::new();
        org_iso_1801351_namespace.insert(
            "org.iso.18013.5.1.age_over_18".to_string(),
            "yes".to_string(),
        );
        org_iso_1801351_namespace.insert(
            "org.iso.18013.5.1.hair_colour".to_string(),
            "brown".to_string(),
        );
        let mut org_iso_1801351_aamva_namespace = HashMap::<String, String>::new();
        org_iso_1801351_aamva_namespace.insert(
            "org.iso.18013.5.aamva.organ_donar".to_string(),
            "yes".to_string(),
        );
        org_iso_1801351_aamva_namespace.insert(
            "org.iso.18013.5.aamva.resident_county".to_string(),
            "United States of America".to_string(),
        );

        namespaces.insert("org.iso.18013.5.1".to_string(), org_iso_1801351_namespace);
        namespaces.insert(
            "org.iso.18013.5.1.aamva".to_string(),
            org_iso_1801351_aamva_namespace,
        );

        let mut authorized_data_elements = Some(HashMap::<String, Vec<String>>::new());
        let mut data_element = HashMap::<String, Vec<String>>::new();
        data_element.insert(
            "org.iso.18013.5.1".to_string(),
            vec!["org.iso.18013.5.1.hair_colour".to_string()],
        );
        authorized_data_elements.insert(data_element);

        let authorized_namespace: Option<Vec<String>> =
            Some(vec!["org.iso.18013.5.1.aamva".to_string()]);

        let mut key_authorization = Some(KeyAuthorization {
            authorized_data_elements: authorized_data_elements,
            authorized_namespaces: authorized_namespace,
        });

        let mut device_key_info = DeviceKeyInfo {
            device_key: CoseKey {
                kty: KeyType::EC,
                alg: SignatureAlgorithm::ES256,
            },
            key_authorization: key_authorization,
        };

        let fixed_offset = FixedOffset::east(0);
        let now = Utc::now();

        let validity_info = ValidityInfo {
            signed: Utc::now(),
            valid_from: Utc::now(),
            valid_until: Utc::now(),
            expected_update: Some(Utc::now()),
        };

        let mut mso = Mso {
            version: "1.0".to_string(),
            digest_algorithm: "SHA-256".to_string(),
            value_digests: HashMap::<String, HashMap<DigestID, Vec<u8>>>::new(),
            device_key_info: device_key_info.clone(),
            doc_type: "org.iso.18013.5.1".to_string(),
            validity_info: validity_info,
        };

        let mut mdoc = Mdoc {
            doc_type: "org.iso.18013.5.1".to_string(),
            namespaces: namespaces.clone(),
            mobile_security_object: mso.clone(),
            issuer_auth: None,
        };

        mdoc
    }
}
