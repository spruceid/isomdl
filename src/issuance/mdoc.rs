use crate::{
    definitions::{
        helpers::{NonEmptyMap, NonEmptyVec, Tag24},
        issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes},
        DeviceKeyInfo, DigestAlgorithm, DigestId, DigestIds, IssuerSignedItem, Mso, ValidityInfo,
    },
    issuance::x5chain::{X5Chain, X5CHAIN_HEADER_LABEL},
};
use anyhow::{anyhow, Result};
use cose_rs::{
    algorithm::SignatureAlgorithm,
    sign1::{CoseSign1, HeaderMap},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{Signature, Signer};
use std::collections::{HashMap, HashSet};

pub type Namespaces = HashMap<String, HashMap<String, CborValue>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Representation of an issued mdoc.
pub struct Mdoc {
    pub doc_type: String,
    pub mso: Mso,
    pub namespaces: IssuerNamespaces,
    pub issuer_auth: CoseSign1,
}

#[derive(Debug, Clone)]
pub struct MdocPreparation {
    doc_type: String,
    mso: Mso,
    namespaces: IssuerNamespaces,
    x5chain: X5Chain,
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
            authorizations.validate()?;
        }

        let issuer_namespaces = to_issuer_namespaces(namespaces)?;
        let value_digests = digest_namespaces(&issuer_namespaces, digest_algorithm)?;

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

    pub fn issue<S, Sig>(
        doc_type: String,
        namespaces: Namespaces,
        x5chain: X5Chain,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        signer: S,
    ) -> Result<Mdoc>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: Signature,
    {
        Self::prepare_mdoc(
            doc_type,
            namespaces,
            x5chain,
            validity_info,
            digest_algorithm,
            device_key_info,
        )?
        .complete(signer)
    }
}

impl MdocPreparation {
    pub fn complete<S, Sig>(self, signer: S) -> Result<Mdoc>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: Signature,
    {
        let MdocPreparation {
            doc_type,
            namespaces,
            mso,
            x5chain,
        } = self;

        // encode mso to cbor
        let mso_bytes = serde_cbor::to_vec(&Tag24::new(&mso)?)?;

        let mut unprotected_headers = HeaderMap::default();
        unprotected_headers.insert_i(X5CHAIN_HEADER_LABEL, x5chain.into_cbor());

        let cose_sign1 = CoseSign1::builder()
            .payload(mso_bytes)
            .unprotected(unprotected_headers)
            .sign(&signer)
            .map_err(|error| anyhow!("error signing mso: {error}"))?;

        let mdoc = Mdoc {
            doc_type,
            mso,
            namespaces,
            issuer_auth: cose_sign1,
        };

        Ok(mdoc)
    }
}

fn to_issuer_namespaces(namespaces: Namespaces) -> Result<IssuerNamespaces> {
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

fn to_issuer_signed_items(
    elements: HashMap<String, CborValue>,
) -> impl Iterator<Item = IssuerSignedItem> {
    let mut used_ids = HashSet::new();
    elements.into_iter().map(move |(key, value)| {
        let digest_id = generate_digest_id(&mut used_ids);
        let random = Vec::from(rand::thread_rng().gen::<[u8; 16]>()).into();
        IssuerSignedItem {
            digest_id,
            random,
            element_identifier: key,
            element_value: value,
        }
    })
}

fn digest_namespaces(
    namespaces: &IssuerNamespaces,
    digest_algorithm: DigestAlgorithm,
) -> Result<HashMap<String, DigestIds>> {
    namespaces
        .iter()
        .map(|(name, elements)| Ok((name.clone(), digest_namespace(elements, digest_algorithm)?)))
        .collect()
}

fn digest_namespace(
    elements: &[IssuerSignedItemBytes],
    digest_algorithm: DigestAlgorithm,
) -> Result<DigestIds> {
    let mut used_ids = elements
        .iter()
        .map(|item| item.as_ref().digest_id)
        .collect();

    // Generate X random digests to avoid leaking information.
    let random_ids = std::iter::repeat_with(|| generate_digest_id(&mut used_ids));
    let random_bytes = std::iter::repeat_with(|| {
        std::iter::repeat_with(|| rand::thread_rng().gen::<u8>())
            .take(512)
            .collect()
    });
    let random_digests = random_ids
        .zip(random_bytes)
        .map(Result::<_, anyhow::Error>::Ok)
        .take(rand::thread_rng().gen_range(5..10));

    elements
        .iter()
        .map(|item| Ok((item.as_ref().digest_id, serde_cbor::to_vec(item)?)))
        .chain(random_digests)
        .map(|result| {
            let (digest_id, bytes) = result?;
            let digest = match digest_algorithm {
                DigestAlgorithm::SHA256 => Sha256::digest(bytes).to_vec(),
                DigestAlgorithm::SHA384 => Sha384::digest(bytes).to_vec(),
                DigestAlgorithm::SHA512 => Sha512::digest(bytes).to_vec(),
            };
            Ok((digest_id, digest.into()))
        })
        .collect()
}

fn generate_digest_id(used_ids: &mut HashSet<DigestId>) -> DigestId {
    let mut digest_id;
    loop {
        digest_id = rand::thread_rng().gen();
        if used_ids.insert(digest_id) {
            break;
        }
    }
    digest_id
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
    use crate::definitions::KeyAuthorizations;
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePrivateKey;
    use time::OffsetDateTime;

    static ISSUER_CERT: &[u8] = include_bytes!("../../test/issuance/256-cert.der");
    static ISSUER_KEY: &str = include_str!("../../test/issuance/256-key.pem");

    #[test]
    fn issue_minimal_mdoc() {
        let doc_type = String::from("org.iso.18013.5.1.mDL");

        let mdl_namespace = String::from("org.iso.18013.5.1");
        let mdl_elements = [
            ("family_name".to_string(), "Smith".to_string().into()),
            ("given_name".to_string(), "Alice".to_string().into()),
            ("document_number".to_string(), "I8889680".to_string().into()),
            (
                "portrait".to_string(),
                CborValue::Bytes(include_bytes!("/home/jward/Downloads/portrait.jpg").to_vec()),
            ),
        ]
        .into_iter()
        .collect();
        let namespaces = [(mdl_namespace.clone(), mdl_elements)]
            .into_iter()
            .collect();

        let x5chain = X5Chain::builder()
            .with_der(ISSUER_CERT.to_vec())
            .unwrap()
            .build()
            .unwrap();

        let validity_info = ValidityInfo {
            signed: OffsetDateTime::now_utc(),
            valid_from: OffsetDateTime::now_utc(),
            valid_until: OffsetDateTime::now_utc(),
            expected_update: None,
        };

        let digest_algorithm = DigestAlgorithm::SHA256;

        use crate::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
        use elliptic_curve::sec1::ToEncodedPoint;
        use rand::{rngs::StdRng, SeedableRng};

        let der = include_str!("../../test/issuance/device_key.b64");
        let der_bytes = base64::decode(der).unwrap();
        let key = p256::SecretKey::from_sec1_der(&der_bytes).unwrap();
        let pub_key = key.public_key();
        let ec = pub_key.to_encoded_point(false);
        let x = ec.x().unwrap().to_vec();
        let y = EC2Y::Value(ec.y().unwrap().to_vec());
        let device_key = CoseKey::EC2 {
            crv: EC2Curve::P256,
            x,
            y,
        };
        let device_key_info = DeviceKeyInfo {
            device_key,
            key_authorizations: Some(KeyAuthorizations {
                namespaces: Some(NonEmptyVec::new(mdl_namespace)),
                data_elements: None,
            }),
            key_info: None,
        };

        let signer: p256::ecdsa::SigningKey = p256::SecretKey::from_pkcs8_pem(ISSUER_KEY)
            .expect("failed to parse pem")
            .into();

        let mdoc = Mdoc::issue(
            doc_type,
            namespaces,
            x5chain,
            validity_info,
            digest_algorithm,
            device_key_info,
            signer,
        )
        .expect("failed to issue mdoc");

        //use crate::presentation::Stringify;
        //let doc: crate::presentation::device::Document = mdoc.into();
        //use std::io::Write;
        //std::fs::File::create("remove_me/doc_with_portrait")
        //    .unwrap()
        //    .write_all(doc.stringify().unwrap().as_bytes());
    }
}
