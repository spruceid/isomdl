use anyhow::{anyhow, Result};
use aws_nitro_enclaves_cose::{
    crypto::{Openssl, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey},
    header_map::HeaderMap,
    sign, CoseSign1,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::collections::{HashMap, HashSet};

mod bytestr;
use bytestr::ByteStr;
mod cose_key;
pub use cose_key::CoseKey;
mod tag24;
use tag24::Tag24;
mod validity_info;
pub use validity_info::ValidityInfo;
mod x5chain;
pub use x5chain::{Builder, X5Chain};

const X5CHAIN: i128 = 33;

type Namespaces = HashMap<String, HashMap<String, CborValue>>;
type DigestIds = HashMap<DigestId, ByteStr>;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    #[serde(default, skip_serializing_if = "IssuerNamespaces::is_empty")]
    namespaces: IssuerNamespaces,
    issuer_auth: CoseSign1,
}

pub type IssuerNamespaces = HashMap<String, Tag24<IssuerSignedItem>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    #[serde(rename = "digestID")]
    digest_id: u64,
    random: ByteStr,
    element_identifier: String,
    element_value: CborValue,
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

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
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

        // encode mso to cbor
        let mso_bytes = serde_cbor::to_vec(&Tag24::new(self.mobile_security_object.clone()))?;

        //headermap should contain alg header and x5chain header
        let alg_header_map: HeaderMap = signer_algorithm.into();

        let x5chain_cbor = self.x5chain.into_cbor()?;
        let mut cert_header_map = HeaderMap::new();
        cert_header_map.insert(serde_cbor::Value::Integer(X5CHAIN), x5chain_cbor);

        let cose_sign1 = sign::CoseSign1::new_with_protected::<Openssl>(
            &mso_bytes,
            &alg_header_map,
            &cert_header_map,
            &signer,
        )
        .map_err(|error| anyhow!("error signing mso: {error}"))?;

        let mdoc = Mdoc {
            doc_type: self.doc_type,
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
                    let random: ByteStr = Vec::from(rand::thread_rng().gen::<[u8; 16]>()).into();
                    let issuer_signed_item = IssuerSignedItem {
                        digest_id,
                        random,
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

#[cfg(test)]
pub mod tests {
    const PEM_FILE: &'static str = include_str!("../../test.pem");

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
