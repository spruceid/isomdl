use aws_nitro_enclaves_cose::crypto::{Hash, SigningPrivateKey};
use aws_nitro_enclaves_cose::header_map::HeaderMap;
use aws_nitro_enclaves_cose::sign;
use chrono::{DateTime, FixedOffset, Offset, Utc};
use ecdsa::{signature::Signature, signature::Signer, SigningKey};
use openssl::pkey::{PKey, Private};
use p256::NistP256;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_cbor;
use serde_json::Value;
use std::collections::HashMap;
use x509_parser::{prelude::*, public_key::PublicKey};

pub struct Mdoc {
    doc_type: String,
    namespaces: HashMap<String, HashMap<String, String>>,
    mobile_security_object: Mso,
    issuer_auth: Value,
}

#[derive(Clone, Debug)]
pub struct Namespaces {
    namespaces: HashMap<String, HashMap<String, String>>,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct Payload {
    version: String,
    digest_algorithm: String, // must be one of SHA-256, SHA-384, SHA-512
    value_digests: Vec<HashMap<String, HashMap<String, String>>>,
    device_key_info: DeviceKeyInfo,
}

#[derive(Clone, Debug)]
pub struct DeviceKeyInfo {
    device_key: SigningKey<NistP256>,
    key_authorization: Option<KeyAuthorization>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeyAuthorization {
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_namespaces: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_data_elements: Option<HashMap<String, Vec<String>>>,
}

#[derive(Clone, Debug)]
// To Do: change datetimes to more specific types for mDL
pub struct ValidityInfo {
    signed: DateTime<Utc>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    expected_update: Option<DateTime<Utc>>,
}

pub struct IssuerSignedItem {
    digest_id: i32,
    random: String, //bstr
    element_identifier: String,
    element_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tdate {
    tdate: DateTime<FixedOffset>,
}

impl Mdoc {
    pub fn issue_credential(
        self,
        doc_type: String,
        namespaces: Namespaces,
        device_key: String,
        device_key_info: DeviceKeyInfo,
        issuerx5chain: X509Certificate,
        validity_info: ValidityInfo,
        signing_alg: String,
        external_signer: String,
        private_key: PKey<Private>,
    ) -> Mdoc {
        //generate signing key

        //for now using p256
        // use p256::ecdsa::signature::{Signature, Signer};
        // let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
        // if curve != "P-256" {
        //     return Err(Error::CurveNotImplemented(curve.to_string()));
        // }
        // let secret_key = p256::SecretKey::try_from(ec)?;
        // let signing_key = p256::ecdsa::SigningKey::from(secret_key);
        // let sig: p256::ecdsa::Signature = signing_key.try_sign(data)?;
        // sig.as_bytes().to_vec();

        //generate mso
        let placeholder_value = Value::String("placeholder".to_string());
        let value_digest = Self::digest_namespaces(self, namespaces, device_key_info.clone());
        let mso = Mso {
            version: "1.0".to_string(),
            digest_algorithm: "SHA-256".to_string(),
            value_digests: value_digest,
            device_key_info: device_key_info,
            doc_type: doc_type,
            validity_info: validity_info,
        };

        //encode mso to cbor

        //load mso bytes into a Cose_Sign1 object as IssuerAuth
        let mobile_security_object_bytes = MobileSecurityObjectBytes { data: vec![] };
        let header_map = HeaderMap::new();
        // let mut sign1 = sign::CoseSign1::new::<dyn Hash>(
        //     &mobile_security_object_bytes.data,
        //     &header_map,
        //     &private_key,
        // );

        unimplemented!()
    }

    pub fn digest_namespaces(
        self,
        namespaces: Namespaces,
        device_key_info: DeviceKeyInfo,
    ) -> HashMap<String, HashMap<String, ecdsa::Signature<NistP256>>> {
        println!("namespaces: {:?}", namespaces.namespaces);

        let mut value_digest =
            HashMap::<String, HashMap<String, ecdsa::Signature<NistP256>>>::new();

        let signing_key = device_key_info.device_key; // Serialize with `::to_bytes()`

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

            let mut value_digest =
                HashMap::<String, HashMap<String, ecdsa::Signature<NistP256>>>::new();

            for namespace in authorized_namespaces {
                let digest_map = namespaces.namespaces.get(&namespace).unwrap().clone();
                let mut digest = HashMap::<String, ecdsa::Signature<NistP256>>::new();
                for (key, value) in digest_map {
                    let mut signed_digest = signing_key.sign(&value.clone().into_bytes());
                    digest.insert(key.to_string(), signed_digest);
                }
                value_digest.insert(namespace, digest.clone());
            }

            println!("value_digest: {:?}", value_digest);

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

            println!("value_digest: {:?}", value_digest);
        };

        value_digest
    }

    pub fn to_cbor(mdoc: Mdoc) -> Vec<u8> {
        let cbor_mdoc = serde_cbor::to_vec(&mdoc);
        cbor_mdoc
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::mdoc;
    use p256::NistP256;

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

    pub async fn sign_mso() {}

    pub async fn cbor_encode_mdoc() {}

    #[test]
    pub fn generate_keys() {
        let signing_key = SigningKey::<NistP256>::random(&mut OsRng); // Serialize with `::to_bytes()`
        let message =
            b"ECDSA proves knowledge of a secret number in the context of a single message";
        let signature = signing_key.sign(message);
        println!("signature: {:?}", signature);
        println!("signing key: {:?}", signing_key);
    }

    #[test]
    pub fn test_digest_namespaces() {
        //set up some data to enter into an mdoc
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
            vec!["hair_colour".to_string()],
        );
        authorized_data_elements.insert(data_element);

        let authorized_namespace: Option<Vec<String>> =
            Some(vec!["org.iso.18013.5.1.aamva".to_string()]);

        let mut key_authorization = Some(KeyAuthorization {
            authorized_data_elements: authorized_data_elements,
            authorized_namespaces: authorized_namespace,
        });

        let mut device_key_info = DeviceKeyInfo {
            device_key: SigningKey::<NistP256>::random(&mut OsRng),
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
            issuer_auth: Value::String("placeholder".to_string()),
        };

        let value_digests = mdoc.digest_namespaces(namespaces, device_key_info);
        mso.value_digests = value_digests;
    }
}
