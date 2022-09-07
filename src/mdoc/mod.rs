use anyhow::{anyhow, Result};
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
use ring::digest::{Algorithm as RingDigestAlgorithm, Context, Digest, SHA256};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_cbor::{self, value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::{HashMap, HashSet};
use std::str::Bytes;

mod bytestr;
use bytestr::ByteStr;
mod cose_key;
pub use cose_key::CoseKey;
mod validity_info;
pub use validity_info::ValidityInfo;
mod x5chain;
pub use x5chain::{Builder, X5Chain};

const ALG: i128 = 1;
const X5CHAIN: i128 = 33;
const PEM_FILE: &'static str = include_str!("../../test.pem");

type Namespaces = HashMap<String, HashMap<String, CborValue>>;
type DigestIds = HashMap<DigestId, ByteStr>;
type IssuerSignedItemBytes = [u8];
type DigestId = u64;

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
#[serde(rename_all = "camelCase")]
pub struct Mso {
    version: String,
    digest_algorithm: DigestAlgorithm,
    value_digests: HashMap<String, DigestIds>,
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
    namespace: HashMap<DigestId, Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MobileSecurityObjectBytes {
    data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    device_key: CoseKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_authorization: Option<KeyAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_info: Option<HashMap<i128, CborValue>>,
}

pub trait Signer {
    fn alg() {}

    fn sign() {}
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeyAuthorization {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    authorized_namespaces: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    authorized_data_elements: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Copy, Deserialize, Serialize)]
pub enum DigestAlgorithm {
    #[serde(rename = "SHA-256")]
    SHA256,
    #[serde(rename = "SHA-384")]
    SHA384,
    #[serde(rename = "SHA-512")]
    SHA512,
}

impl PreparationMdoc {
    pub fn complete<T: SigningPrivateKey + SigningPublicKey>(self, signer: T) -> Result<Mdoc> {
        let signer_algorithm = signer
            .get_parameters()
            .map_err(|error| anyhow!("error getting key parameters: {error}"))?
            .0;

        match (self.x5chain.key_algorithm()?, signer_algorithm) {
            (SignatureAlgorithm::ES256, SignatureAlgorithm::ES256) => (),
            (SignatureAlgorithm::ES384, SignatureAlgorithm::ES384) => (),
            (SignatureAlgorithm::ES512, SignatureAlgorithm::ES512) => (),
            _ => Err(anyhow!(
                "provided signer's algorithm does not match X509 cert"
            ))?,
        }

        //encode mso to cbor
        let mobile_security_object_bytes = to_cbor(self.mobile_security_object.clone())?;

        //headermap should contain alg header and x5chain header
        let mut alg_header_map: HeaderMap = signer_algorithm.into();
        let mut buf: Vec<u8> = vec![];

        let x5chain_cbor = self.x5chain.into_cbor()?;
        let mut cert_header_map = HeaderMap::new();
        cert_header_map.insert(serde_cbor::Value::Integer(X5CHAIN), x5chain_cbor);

        let cose_sign1 = sign::CoseSign1::new_with_protected::<Openssl>(
            &mobile_security_object_bytes,
            &alg_header_map,
            &cert_header_map,
            &signer,
        )
        .map_err(|error| anyhow!("error signing mso: {error}"))?;

        let mdoc = Mdoc {
            doc_type: "org.iso.18013.5.1".to_string(),
            namespaces: self.namespaces,
            mobile_security_object: self.mobile_security_object,
            issuer_auth: Some(cose_sign1),
        };

        Ok(mdoc)
    }
}

impl Mdoc {
    pub fn prepare_mdoc(
        doc_type: String,
        namespaces: Namespaces,
        x5chain: X5Chain,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
    ) -> Result<PreparationMdoc> {
        let value_digests = Mdoc::digest_namespaces(&namespaces, digest_algorithm)?;

        let mobile_security_object = Mso {
            version: "1.0".to_string(),
            digest_algorithm,
            value_digests,
            device_key_info,
            doc_type: doc_type.clone(),
            validity_info,
        };

        let preparation_mdoc = PreparationMdoc {
            doc_type,
            namespaces,
            mobile_security_object,
            x5chain,
        };

        Ok(preparation_mdoc)
    }

    pub fn digest_namespaces(
        namespaces: &Namespaces,
        digest_algorithm: DigestAlgorithm,
    ) -> Result<HashMap<String, DigestIds>> {
        fn digest_namespace(
            elements: &HashMap<String, CborValue>,
            digest_algorithm: DigestAlgorithm,
        ) -> Result<DigestIds> {
            let mut used_ids: HashSet<u64> = HashSet::new();
            elements
                .iter()
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
                    return Ok((digest_id, digest.as_ref().to_vec().into()));
                })
                .collect()
        }

        namespaces
            .iter()
            .map(|(name, elements)| {
                Ok((name.clone(), digest_namespace(elements, digest_algorithm)?))
            })
            .collect()
    }
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
            value_digests: HashMap::<String, DigestIds>::new(),
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
