use anyhow::Result;
use aws_nitro_enclaves_cose::crypto::{
    Hash, MessageDigest, Openssl, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey,
};
use aws_nitro_enclaves_cose::error::CoseError;
use aws_nitro_enclaves_cose::header_map::HeaderMap;
use aws_nitro_enclaves_cose::{sign, CoseSign1};
use cddl::{parser::cddl_from_str, validate_json_from_str};
use chrono::{DateTime, FixedOffset, Offset, Utc};
use der::Encode;
use der::Writer;
use ecdsa::{signature::Signature, signature::Signer, SigningKey};
use openssl::ec::EcKey;
use openssl::pkey::{Id, PKey, Private, Public};
use p256::{AffinePoint, NistP256, PublicKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_cbor::{self, value};
use serde_json::Value;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::HashMap;
use x509_parser::pem::Pem;
use x509_parser::prelude::*;
use x509_parser::x509::X509Version;
use zeroize::Zeroize;

const ALG: i128 = 1;
const X5CHAIN: i128 = 33;

#[derive(Serialize, Deserialize)]
pub struct Mdoc {
    doc_type: String,
    namespaces: HashMap<String, HashMap<String, String>>,
    mobile_security_object: Mso,
    issuer_auth: Option<CoseSign1>,
}

#[derive(Clone, Debug)]
pub struct Namespaces {
    namespaces: HashMap<String, HashMap<String, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mso {
    version: String,
    digest_algorithm: String,
    value_digests: HashMap<String, HashMap<String, ecdsa::Signature<NistP256>>>,
    device_key_info: DeviceKeyInfo,
    doc_type: String,
    validity_info: ValidityInfo,
}

#[derive(Serialize, Deserialize)]
pub struct IssuerAuth {
    issuer_auth: Value,
}

pub struct DigestIDs {
    digest_ids: HashMap<String, String>,
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

pub struct IssuerSignedItem {
    digest_id: i32,
    random: String, //bstr
    element_identifier: String,
    element_value: String,
}

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

impl Mdoc {
    pub fn issue<T: SigningPrivateKey + SigningPublicKey + DeviceKeyInfoTrait>(
        self,
        doc_type: String,
        namespaces: Namespaces,
        issuerx5chain: Vec<String>,
        validity_info: ValidityInfo,
        digest_algorithm: String,
        //external_signer: String,
        signer: T,
    ) -> Mdoc {
        //generate mso
        let value_digest = self.digest_namespaces(namespaces, signer.get_device_key_info());
        let mso = Mso {
            version: "1.0".to_string(),
            digest_algorithm,
            value_digests: value_digest,
            device_key_info: signer.get_device_key_info(),
            doc_type: doc_type,
            validity_info: validity_info,
        };

        //encode mso to cbor
        let mobile_security_object_bytes = to_cbor(mso);

        //load mso bytes into a Cose_Sign1 object as IssuerAuth
        //headermap should contain alg header and x5chain header
        let mut alg_header_map: HeaderMap = signer.get_device_key_info().device_key.alg.into();
        let mut buf: Vec<u8> = vec![];

        let cert_bytes = der::Encode::encode_to_vec(&issuerx5chain, &mut buf);
        println!("cert_bytes: {:?}", cert_bytes);

        let cbor_cert_chain: Vec<CborValue> = issuerx5chain
            .into_iter()
            .map(|s| s.as_bytes().to_vec())
            .map(|v| serde_cbor::Value::Bytes(v))
            .collect();

        let mut cert_header_map = HeaderMap::new();
        cert_header_map.insert(
            serde_cbor::Value::Integer(X5CHAIN),
            serde_cbor::Value::Array(cbor_cert_chain),
        );
        let cose_sign1 = sign::CoseSign1::new_with_protected::<Openssl>(
            &mobile_security_object_bytes.unwrap(),
            &alg_header_map,
            &cert_header_map,
            &signer,
        );

        println!("cose_sign1: {:?}", cose_sign1);

        unimplemented!()
    }

    pub fn digest_namespaces(
        self,
        namespaces: Namespaces,
        device_key_info: DeviceKeyInfo,
    ) -> HashMap<String, HashMap<String, ecdsa::Signature<NistP256>>> {
        let mut value_digest =
            HashMap::<String, HashMap<String, ecdsa::Signature<NistP256>>>::new();

        let signing_key = SigningKey::<NistP256>::random(&mut OsRng); // do this somewhere else and hand function the key`

        let key_authorization = device_key_info.key_authorization;

        if key_authorization.is_none() {
            //grab all data elements
        } else {
            //grab all authorized data elements
            let authorized_namespaces = key_authorization
                .clone()
                .unwrap()
                .authorized_namespaces
                .unwrap();
            let authorized_data_elements =
                key_authorization.unwrap().authorized_data_elements.unwrap();

            for namespace in authorized_namespaces {
                let digest_map = namespaces.namespaces.get(&namespace).unwrap().clone();
                let mut digest = HashMap::<String, ecdsa::Signature<NistP256>>::new();
                for (key, value) in digest_map {
                    let mut signed_digest = signing_key.sign(&value.clone().into_bytes());
                    digest.insert(key.to_string(), signed_digest);
                }
                value_digest.insert(namespace, digest.clone());
            }

            for (key, value) in authorized_data_elements {
                let digest_map = namespaces.namespaces.get(&key).unwrap();
                let mut digest = HashMap::<String, ecdsa::Signature<NistP256>>::new();

                for val in value {
                    let digest_value = digest_map.get(&val).unwrap();
                    let signed_digest = signing_key.sign(&digest_value.clone().into_bytes());
                    digest.insert(val, signed_digest);
                }
                value_digest.insert(key, digest);
            }
        };

        value_digest
    }
}

pub struct PrivateKey {
    pkey: SigningKey<NistP256>,
}

impl SigningPrivateKey for PrivateKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CoseError> {
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

impl DeviceKeyInfoTrait for PrivateKey {
    fn get_alg(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ES256
    }

    fn get_device_key_info(&self) -> DeviceKeyInfo {
        let cose_key = CoseKey {
            kty: KeyType::EC,
            alg: SignatureAlgorithm::ES256,
        };
        DeviceKeyInfo {
            device_key: (cose_key),
            key_authorization: None,
        }
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

pub trait DeviceKeyInfoTrait {
    fn get_alg(&self) -> SignatureAlgorithm;
    fn get_kty(&self) -> KeyType;
    fn get_device_key_info(&self) -> DeviceKeyInfo;
}

pub fn generate_keys() -> (PublicKey, SigningKey<NistP256>) {
    let affine_point = AffinePoint::GENERATOR;
    let public_key = PublicKey::try_from(affine_point).unwrap();
    let signing_key = SigningKey::<NistP256>::random(&mut OsRng); // Serialize with `::to_bytes()`

    (public_key, signing_key)
}

pub fn to_cbor(mso: Mso) -> Result<Vec<u8>, serde_cbor::Error> {
    let cbor_mdoc = serde_cbor::to_vec(&mso);
    cbor_mdoc
}

pub fn from_cbor(mso_bytes: Vec<u8>) -> Result<Mso, serde_cbor::Error> {
    let mso: Result<Mso, serde_cbor::Error> = serde_cbor::from_slice(&mso_bytes);
    mso
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::mdoc;
    use p256::NistP256;
    use serde_cbor::value;

    pub async fn generate_mso(
        doc_type: String,
        namespaces: Namespaces,
        device_key: String,
        device_key_info: DeviceKeyInfo,
        issuerx5chain: X509Certificate<'_>,
        validity_info: ValidityInfo,
        signing_alg: String,
        external_signer: String,
    ) {
    }

    #[test]
    pub fn issue_credential_test() {
        let mut info_mdoc = load_mock_data();
        let namespaces = Namespaces {
            namespaces: info_mdoc.namespaces.clone(),
        };
        let device_key_info = info_mdoc.mobile_security_object.device_key_info.clone();
        let doc_type = info_mdoc.doc_type.clone();
        let validity_info = info_mdoc.mobile_security_object.validity_info.clone();
        let signing_alg = info_mdoc.mobile_security_object.digest_algorithm.clone();

        let value_digest = info_mdoc
            .digest_namespaces(namespaces.clone(), device_key_info.clone())
            .clone();

        let keys = generate_keys(); //move out of mdoc?
        let sig_key = keys.1.clone();
        let priv_key = PrivateKey { pkey: sig_key };

        //parse x509 from pem

        static IGCA_PEM: &str = "./test.pem";
        let data = std::fs::read(IGCA_PEM).expect("Could not read file");
        let issuerx5 = serde_json::to_string(&data).unwrap();
        println!("data: {:?}", data.len());
        println!("issuerx5: {:?}", issuerx5);

        let issuerx5chain = vec![issuerx5];

        let mut mdoc = load_mock_data();

        let issued_credential = mdoc.issue(
            doc_type,
            namespaces,
            issuerx5chain,
            validity_info,
            signing_alg,
            priv_key,
        );
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
        let namespaces = Namespaces {
            namespaces: mdoc.namespaces.clone(),
        };
        let device_key_info = mdoc.mobile_security_object.device_key_info.clone();

        let value_digests = mdoc.digest_namespaces(namespaces, device_key_info);
        //asserteq
    }

    pub fn load_mock_data() -> Mdoc {
        let mut namespaces: Namespaces = Namespaces {
            namespaces: HashMap::<String, HashMap<String, String>>::new(),
        };
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

        namespaces
            .namespaces
            .insert("org.iso.18013.5.1".to_string(), org_iso_1801351_namespace);
        namespaces.namespaces.insert(
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
            value_digests: HashMap::<String, HashMap<String, ecdsa::Signature<NistP256>>>::new(),
            device_key_info: device_key_info.clone(),
            doc_type: "org.iso.18013.5.1".to_string(),
            validity_info: validity_info,
        };

        let mut mdoc = Mdoc {
            doc_type: "org.iso.18013.5.1".to_string(),
            namespaces: namespaces.namespaces.clone(),
            mobile_security_object: mso.clone(),
            issuer_auth: None,
        };

        mdoc
    }
}
