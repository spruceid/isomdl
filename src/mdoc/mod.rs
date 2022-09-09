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
mod cose_key;
mod non_empty_map;
mod non_empty_vec;
mod tag24;
mod validity_info;
mod x5chain;

use bytestr::ByteStr;
pub use cose_key::CoseKey;
pub use non_empty_map::NonEmptyMap;
pub use non_empty_vec::NonEmptyVec;
pub use tag24::Tag24;
pub use validity_info::ValidityInfo;
pub use x5chain::{Builder, X5Chain};

const X5CHAIN: i128 = 33;

pub type Namespaces = HashMap<String, HashMap<String, CborValue>>;
pub type DigestIds = HashMap<DigestId, ByteStr>;
pub type DigestId = u64;
pub type IssuerNamespaces = NonEmptyMap<String, NonEmptyVec<Tag24<IssuerSignedItem>>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Representation of an issued mdoc.
pub struct Mdoc {
    doc_type: String,
    namespaces: IssuerNamespaces,
    issuer_auth: CoseSign1,
}

#[derive(Debug, Clone)]
pub struct MdocPreparation {
    doc_type: String,
    namespaces: IssuerNamespaces,
    mso: Mso,
    x5chain: X5Chain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mso {
    pub version: String,
    pub digest_algorithm: DigestAlgorithm,
    pub value_digests: HashMap<String, DigestIds>,
    pub device_key_info: DeviceKeyInfo,
    pub doc_type: String,
    pub validity_info: ValidityInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "nameSpaces"
    )]
    pub namespaces: Option<IssuerNamespaces>,
    pub issuer_auth: CoseSign1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    #[serde(rename = "digestID")]
    pub digest_id: u64,
    pub random: ByteStr,
    pub element_identifier: String,
    pub element_value: CborValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    pub device_key: CoseKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_authorizations: Option<KeyAuthorizations>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_info: Option<HashMap<i128, CborValue>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorizations {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "nameSpaces"
    )]
    pub namespaces: Option<NonEmptyVec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_elements: Option<NonEmptyMap<String, NonEmptyVec<String>>>,
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

impl MdocPreparation {
    pub fn complete<T: SigningPrivateKey + SigningPublicKey>(self, signer: T) -> Result<Mdoc> {
        let MdocPreparation {
            doc_type,
            namespaces,
            mso,
            x5chain,
        } = self;

        let signer_algorithm = signer
            .get_parameters()
            .map_err(|error| anyhow!("error getting signer parameters: {error}"))?
            .0;

        match (x5chain.key_algorithm()?, signer_algorithm) {
            (SignatureAlgorithm::ES256, SignatureAlgorithm::ES256) => (),
            (SignatureAlgorithm::ES384, SignatureAlgorithm::ES384) => (),
            (SignatureAlgorithm::ES512, SignatureAlgorithm::ES512) => (),
            (chain_alg, signer_alg) => Err(anyhow!(
                "signature algorithm does not match: expected '{:?}' (from x5chain), found '{:?}' (from signer)"
                , chain_alg, signer_alg
            ))?,
        }

        // encode mso to cbor
        let mso_bytes = serde_cbor::to_vec(&Tag24::new(mso)?)?;

        //headermap should contain alg header and x5chain header
        let protected_headers: HeaderMap = signer_algorithm.into();

        let mut unprotected_headers = HeaderMap::new();
        unprotected_headers.insert(serde_cbor::Value::Integer(X5CHAIN), x5chain.into_cbor()?);

        let cose_sign1 = sign::CoseSign1::new_with_protected::<Openssl>(
            &mso_bytes,
            &protected_headers,
            &unprotected_headers,
            &signer,
        )
        .map_err(|error| anyhow!("error signing mso: {error}"))?;

        let mdoc = Mdoc {
            doc_type,
            namespaces,
            issuer_auth: cose_sign1,
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
    ) -> Result<MdocPreparation> {
        if let Some(authorizations) = &device_key_info.key_authorizations {
            if !authorizations.is_valid() {
                return Err(anyhow!("key authorizations for device key are invalid: an authorized namespace cannot be included in the authorized data elements map"));
            }
        }

        let issuer_namespaces = Mdoc::to_issuer_namespaces(namespaces)?;
        let value_digests = Mdoc::digest_namespaces(&issuer_namespaces, digest_algorithm)?;

        let mso = Mso {
            version: "1.0".to_string(),
            digest_algorithm,
            value_digests,
            device_key_info,
            doc_type: doc_type.clone(),
            validity_info,
        };

        let preparation_mdoc = MdocPreparation {
            doc_type,
            namespaces: issuer_namespaces,
            mso,
            x5chain,
        };

        Ok(preparation_mdoc)
    }

    pub fn to_issuer_namespaces(namespaces: Namespaces) -> Result<IssuerNamespaces> {
        fn to_issuer_signed_items(
            elements: HashMap<String, CborValue>,
        ) -> impl Iterator<Item = IssuerSignedItem> {
            let mut used_ids: HashSet<u64> = HashSet::new();
            elements.into_iter().map(move |(key, value)| {
                let mut digest_id;
                loop {
                    digest_id = rand::thread_rng().gen();
                    if used_ids.insert(digest_id) {
                        break;
                    }
                }
                let random: ByteStr = Vec::from(rand::thread_rng().gen::<[u8; 16]>()).into();
                IssuerSignedItem {
                    digest_id,
                    random,
                    element_identifier: key,
                    element_value: value,
                }
            })
        }

        namespaces
            .into_iter()
            .map(|(name, elements)| {
                to_issuer_signed_items(elements)
                    .map(Tag24::new)
                    .collect::<Result<Vec<Tag24<IssuerSignedItem>>, _>>()
                    .map_err(|err| anyhow!("unable to encode IssuerSignedItem as cbor: {}", err))
                    .and_then(|items| {
                        NonEmptyVec::try_from(items)
                            .map_err(|_| anyhow!("at least one element required in each namespace"))
                    })
                    .map(|elems| (name, elems))
            })
            .collect::<Result<HashMap<String, NonEmptyVec<Tag24<IssuerSignedItem>>>>>()
            .and_then(|namespaces| {
                NonEmptyMap::try_from(namespaces)
                    .map_err(|_| anyhow!("at least one namespace required"))
            })
    }

    pub fn digest_namespaces(
        namespaces: &IssuerNamespaces,
        digest_algorithm: DigestAlgorithm,
    ) -> Result<HashMap<String, DigestIds>> {
        fn digest_namespace(
            elements: &[Tag24<IssuerSignedItem>],
            digest_algorithm: DigestAlgorithm,
        ) -> Result<DigestIds> {
            let ring_alg = match digest_algorithm {
                DigestAlgorithm::SHA256 => &ring::digest::SHA256,
                DigestAlgorithm::SHA384 => &ring::digest::SHA384,
                DigestAlgorithm::SHA512 => &ring::digest::SHA512,
            };
            elements
                .iter()
                .map(|item| {
                    let issuer_signed_item_bytes = serde_cbor::to_vec(item)?;
                    let digest = ring::digest::digest(ring_alg, &issuer_signed_item_bytes);
                    return Ok((
                        item.as_ref().digest_id,
                        digest.as_ref().to_vec().into(),
                    ));
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

impl KeyAuthorizations {
    pub fn is_valid(&self) -> bool {
        if let Some(ns) = &self.namespaces {
            ns.iter().all(|namespace| {
                if let Some(ds) = &self.data_elements {
                    ds.get(namespace).is_none()
                } else {
                    true
                }
            })
        } else {
            true
        }
    }
}
