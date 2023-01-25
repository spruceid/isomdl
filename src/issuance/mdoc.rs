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
    algorithm::{Algorithm, SignatureAlgorithm},
    sign1::{CoseSign1, HeaderMap, PreparedCoseSign1},
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
/// A signed mdoc.
pub struct Mdoc {
    pub doc_type: String,
    pub mso: Mso,
    pub namespaces: IssuerNamespaces,
    pub issuer_auth: CoseSign1,
}

#[derive(Debug, Clone)]
/// An incomplete mdoc, requiring a remotely signed signature to be completed.
pub struct PreparedMdoc {
    doc_type: String,
    mso: Mso,
    namespaces: IssuerNamespaces,
    prepared_sig: PreparedCoseSign1,
}

#[derive(Debug, Clone, Default)]
pub struct Builder {
    doc_type: Option<String>,
    namespaces: Option<Namespaces>,
    validity_info: Option<ValidityInfo>,
    digest_algorithm: Option<DigestAlgorithm>,
    device_key_info: Option<DeviceKeyInfo>,
    x5chain: Option<X5Chain>,
}

impl Mdoc {
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Prepare mdoc for remote signing.
    pub fn prepare(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        x5chain: X5Chain,
        signature_algorithm: Algorithm,
    ) -> Result<PreparedMdoc> {
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

        let mso_bytes = serde_cbor::to_vec(&Tag24::new(&mso)?)?;

        let mut unprotected_headers = HeaderMap::default();
        unprotected_headers.insert_i(X5CHAIN_HEADER_LABEL, x5chain.into_cbor());

        let prepared_sig = CoseSign1::builder()
            .payload(mso_bytes)
            .unprotected(unprotected_headers)
            .signature_algorithm(signature_algorithm)
            .prepare()
            .map_err(|e| anyhow!("error preparing cosesign1: {}", e))?;

        let preparation_mdoc = PreparedMdoc {
            doc_type,
            namespaces: issuer_namespaces,
            mso,
            prepared_sig,
        };

        Ok(preparation_mdoc)
    }

    /// Directly sign and issue an mdoc.
    pub fn issue<S, Sig>(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        x5chain: X5Chain,
        signer: S,
    ) -> Result<Mdoc>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: Signature,
    {
        let prepared_mdoc = Self::prepare(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            x5chain,
            signer.algorithm(),
        )?;

        let signature_payload = prepared_mdoc.signature_payload();
        let signature = signer
            .try_sign(signature_payload)
            .map_err(|e| anyhow!("error signing cosesign1: {}", e))?
            .as_bytes()
            .to_vec();

        Ok(prepared_mdoc.complete(signature))
    }
}

impl PreparedMdoc {
    /// Retrieve the payload for a remote signature.
    pub fn signature_payload(&self) -> &[u8] {
        self.prepared_sig.signature_payload()
    }

    /// Supply the remotely signed signature to complete and issue the prepared mdoc.
    pub fn complete(self, signature: Vec<u8>) -> Mdoc {
        let PreparedMdoc {
            doc_type,
            namespaces,
            mso,
            prepared_sig,
        } = self;

        let issuer_auth = prepared_sig.finalize(signature);

        Mdoc {
            doc_type,
            mso,
            namespaces,
            issuer_auth,
        }
    }
}

impl Builder {
    /// Set the document type.
    pub fn doc_type(mut self, doc_type: String) -> Self {
        self.doc_type = Some(doc_type);
        self
    }

    /// Set the data elements.
    pub fn namespaces(mut self, namespaces: Namespaces) -> Self {
        self.namespaces = Some(namespaces);
        self
    }

    /// Set the validity information
    pub fn validity_info(mut self, validity_info: ValidityInfo) -> Self {
        self.validity_info = Some(validity_info);
        self
    }

    /// Set the digest algorithm to be used for hashing the data elements.
    pub fn digest_algorithm(mut self, digest_algorithm: DigestAlgorithm) -> Self {
        self.digest_algorithm = Some(digest_algorithm);
        self
    }

    /// Set the information about the device key that this mdoc will be issued to.
    pub fn device_key_info(mut self, device_key_info: DeviceKeyInfo) -> Self {
        self.device_key_info = Some(device_key_info);
        self
    }

    /// Set the x5chain of the issuing key.
    pub fn x5chain(mut self, x5chain: X5Chain) -> Self {
        self.x5chain = Some(x5chain);
        self
    }

    /// Prepare the mdoc for remote signing.
    ///
    /// The signature algorithm which the mdoc will be signed with must be known ahead of time as
    /// it is a required field in the signature headers.
    pub fn prepare(self, signature_algorithm: Algorithm) -> Result<PreparedMdoc> {
        let doc_type = self
            .doc_type
            .ok_or_else(|| anyhow!("missing parameter: 'doc_type'"))?;
        let namespaces = self
            .namespaces
            .ok_or_else(|| anyhow!("missing parameter: 'namespaces'"))?;
        let validity_info = self
            .validity_info
            .ok_or_else(|| anyhow!("missing parameter: 'validity_info'"))?;
        let digest_algorithm = self
            .digest_algorithm
            .ok_or_else(|| anyhow!("missing parameter: 'digest_algorithm'"))?;
        let device_key_info = self
            .device_key_info
            .ok_or_else(|| anyhow!("missing parameter: 'device_key_info'"))?;
        let x5chain = self
            .x5chain
            .ok_or_else(|| anyhow!("missing parameter: 'x5chain'"))?;

        Mdoc::prepare(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            x5chain,
            signature_algorithm,
        )
    }

    /// Directly issue an mdoc.
    pub fn issue<S, Sig>(self, signer: S) -> Result<Mdoc>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: Signature,
    {
        let doc_type = self
            .doc_type
            .ok_or_else(|| anyhow!("missing parameter: 'doc_type'"))?;
        let namespaces = self
            .namespaces
            .ok_or_else(|| anyhow!("missing parameter: 'namespaces'"))?;
        let validity_info = self
            .validity_info
            .ok_or_else(|| anyhow!("missing parameter: 'validity_info'"))?;
        let digest_algorithm = self
            .digest_algorithm
            .ok_or_else(|| anyhow!("missing parameter: 'digest_algorithm'"))?;
        let device_key_info = self
            .device_key_info
            .ok_or_else(|| anyhow!("missing parameter: 'device_key_info'"))?;
        let x5chain = self
            .x5chain
            .ok_or_else(|| anyhow!("missing parameter: 'x5chain'"))?;

        Mdoc::issue(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            x5chain,
            signer,
        )
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
        digest_id = rand::thread_rng().gen::<i32>().into();
        if used_ids.insert(digest_id) {
            break;
        }
    }
    digest_id
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
    use crate::definitions::fulldate::FullDate;
    use crate::definitions::namespaces::org_iso_18013_5_1::{Code, DrivingPrivilege};
    use crate::definitions::namespaces::org_iso_18013_5_1_aamva::{self as aamva};
    use crate::definitions::KeyAuthorizations;
    use base64::URL_SAFE_NO_PAD;
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePrivateKey;
    use std::str::FromStr;
    use time::OffsetDateTime;

    static ISSUER_CERT: &[u8] = include_bytes!("../../test/issuance/issuer-cert.pem");
    static ISSUER_KEY: &str = include_str!("../../test/issuance/issuer-key.pem");

    fn mdl_data() -> String {
        base64::encode_config(
            serde_json::json!(
                {
                  "org.iso.18013.5.1.aamva.sex":1,
                  "org.iso.18013.5.1.aamva.given_name_truncation":"N",
                  "org.iso.18013.5.1.aamva.family_name_truncation":"N",
                  "org.iso.18013.5.1.aamva.aamva_version":2,
                  "org.iso.18013.5.1.aamva.domestic_driving_privileges":[
                    {
                      "domestic_vehicle_class":{
                        "domestic_vehicle_class_code":"A",
                        "domestic_vehicle_class_description":"unknown",
                        "issue_date":"2022-08-09",
                        "expiry_date":"2030-10-20"
                      }
                    },
                    {
                      "domestic_vehicle_class":{
                        "domestic_vehicle_class_code":"B",
                        "domestic_vehicle_class_description":"unknown",
                        "issue_date":"2022-08-09",
                        "expiry_date":"2030-10-20"
                      }
                    }
                  ],
                  "org.iso.18013.5.1.family_name":"Doe",
                  "org.iso.18013.5.1.given_name":"John",
                  "org.iso.18013.5.1.birth_date":"1980-10-10",
                  "org.iso.18013.5.1.issue_date":"2020-08-10",
                  "org.iso.18013.5.1.expiry_date":"2030-10-30",
                  "org.iso.18013.5.1.issuing_country":"US",
                  "org.iso.18013.5.1.issuing_authority":"CA DMV",
                  "org.iso.18013.5.1.document_number":"I12345678",
                  "org.iso.18013.5.1.portrait":include_str!("../../test/issuance/portrait.b64u"),
                  "org.iso.18013.5.1.height":170,
                  "org.iso.18013.5.1.eye_colour":"hazel",
                  "org.iso.18013.5.1.driving_privileges":[
                    {
                       "vehicle_category_code":"A",
                       "issue_date":"2022-08-09",
                       "expiry_date":"2030-10-20"
                    },
                    {
                       "vehicle_category_code":"B",
                       "issue_date":"2022-08-09",
                       "expiry_date":"2030-10-20"
                    }
                  ],
                  "org.iso.18013.5.1.un_distinguishing_sign":"USA"
                }
            )
            .to_string(),
            URL_SAFE_NO_PAD,
        )
    }

    #[test]
    fn issue_minimal_mdoc() -> anyhow::Result<()> {
        minimal_test_mdoc()?;
        Ok(())
    }

    pub fn minimal_test_mdoc() -> anyhow::Result<Mdoc> {
        let doc_type = String::from("org.iso.18013.5.1.mDL");

        let mut mdl_data: serde_json::Value =
            String::from_utf8(base64::decode_config(mdl_data(), base64::URL_SAFE_NO_PAD).unwrap())
                .unwrap()
                .parse()
                .unwrap();

        let isomdl_namespace = String::from("org.iso.18013.5.1");
        let isomdl_elements = [
            (
                "family_name".to_string(),
                mdl_data
                    .get("org.iso.18013.5.1.family_name")
                    .ok_or_else(|| {
                        anyhow!("missing required element: org.iso.18013.5.1.family_name")
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        anyhow!("expected string for element: org.iso.18013.5.1.family_name")
                    })?
                    .to_string()
                    .into(),
            ),
            (
                "given_name".to_string(),
                mdl_data
                    .get("org.iso.18013.5.1.given_name")
                    .ok_or_else(|| {
                        anyhow!("missing required element: org.iso.18013.5.1.given_name")
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        anyhow!("expected string for element: org.iso.18013.5.1.given_name")
                    })?
                    .to_string()
                    .into(),
            ),
            (
                "document_number".to_string(),
                mdl_data
                    .get("org.iso.18013.5.1.document_number")
                    .ok_or_else(|| {
                        anyhow!("missing required element: org.iso.18013.5.1.document_number")
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        anyhow!("expected string for element: org.iso.18013.5.1.document_number")
                    })?
                    .to_string()
                    .into(),
            ),
            (
                "issuing_country".to_string(),
                mdl_data
                    .get("org.iso.18013.5.1.issuing_country")
                    .ok_or_else(|| {
                        anyhow!("missing required element: org.iso.18013.5.1.issuing_country")
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        anyhow!("expected string for element: org.iso.18013.5.1.issuing_country")
                    })?
                    .to_string()
                    .into(),
            ),
            (
                "issuing_authority".to_string(),
                mdl_data
                    .get("org.iso.18013.5.1.issuing_authority")
                    .ok_or_else(|| {
                        anyhow!("missing required element: org.iso.18013.5.1.issuing_authority")
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        anyhow!("expected string for element: org.iso.18013.5.1.issuing_authority")
                    })?
                    .to_string()
                    .into(),
            ),
            (
                "un_distinguishing_sign".to_string(),
                mdl_data
                    .get("org.iso.18013.5.1.un_distinguishing_sign")
                    .ok_or_else(|| {
                        anyhow!(
                            "missing required element: org.iso.18013.5.1.un_distinguishing_sign"
                        )
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        anyhow!(
                            "expected string for element: org.iso.18013.5.1.un_distinguishing_sign"
                        )
                    })?
                    .to_string()
                    .into(),
            ),
            (
                "birth_date".to_string(),
                FullDate::from_str(
                    mdl_data
                        .get("org.iso.18013.5.1.birth_date")
                        .ok_or_else(|| {
                            anyhow!("missing required element: org.iso.18013.5.1.birth_date")
                        })?
                        .as_str()
                        .ok_or_else(|| {
                            anyhow!("expected string for element: org.iso.18013.5.1.birth_date")
                        })?,
                )
                .unwrap()
                .into(),
            ),
            (
                "issue_date".to_string(),
                FullDate::from_str(
                    mdl_data
                        .get("org.iso.18013.5.1.issue_date")
                        .ok_or_else(|| {
                            anyhow!("missing required element: org.iso.18013.5.1.issue_date")
                        })?
                        .as_str()
                        .ok_or_else(|| {
                            anyhow!("expected string for element: org.iso.18013.5.1.issue_date")
                        })?,
                )
                .unwrap()
                .into(),
            ),
            (
                "expiry_date".to_string(),
                FullDate::from_str(
                    mdl_data
                        .get("org.iso.18013.5.1.expiry_date")
                        .ok_or_else(|| {
                            anyhow!("missing required element: org.iso.18013.5.1.expiry_date")
                        })?
                        .as_str()
                        .ok_or_else(|| {
                            anyhow!("expected string for element: org.iso.18013.5.1.expiry_date")
                        })?,
                )
                .unwrap()
                .into(),
            ),
            (
                "portrait".to_string(),
                CborValue::Bytes(
                    base64::decode_config(
                        mdl_data
                            .get("org.iso.18013.5.1.portrait")
                            .ok_or_else(|| {
                                anyhow!("missing required element: org.iso.18013.5.1.portrait")
                            })?
                            .as_str()
                            .ok_or_else(|| {
                                anyhow!("expected string for element: org.iso.18013.5.1.portrait")
                            })?,
                        URL_SAFE_NO_PAD,
                    )
                    .unwrap(),
                ),
            ),
            (
                "height".to_string(),
                mdl_data
                    .get("org.iso.18013.5.1.height")
                    .ok_or_else(|| anyhow!("missing required element: org.iso.18013.5.1.height"))?
                    .as_i64()
                    .ok_or_else(|| {
                        anyhow!("expected integer for element: org.iso.18013.5.1.height")
                    })?
                    .into(),
            ),
            (
                "eye_colour".to_string(),
                mdl_data
                    .get("org.iso.18013.5.1.eye_colour")
                    .ok_or_else(|| {
                        anyhow!("missing required element: org.iso.18013.5.1.eye_colour")
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        anyhow!("expected string for element: org.iso.18013.5.1.eye_colour")
                    })?
                    .to_string()
                    .into(),
            ),
            (
                "driving_privileges".to_string(),
                mdl_data
                    .get("org.iso.18013.5.1.driving_privileges")
                    .ok_or_else(|| {
                        anyhow!("missing required element: org.iso.18013.5.1.driving_privileges")
                    })?
                    .as_array()
                    .ok_or_else(|| {
                        anyhow!("expected array for element: org.iso.18013.5.1.driving_privileges")
                    })?
                    .iter()
                    .map(|j| {
                        let vehicle_category_code = j
                            .get("vehicle_category_code")
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .to_string();
                        let issue_date = j
                            .get("issue_date")
                            .map(|s| FullDate::from_str(s.as_str().unwrap()).unwrap());
                        let expiry_date = j
                            .get("expiry_date")
                            .map(|s| FullDate::from_str(s.as_str().unwrap()).unwrap());
                        let codes = j.get("codes").and_then(|v| {
                            NonEmptyVec::maybe_new(
                                v.as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|s| {
                                        let code =
                                            s.get("code").unwrap().as_str().unwrap().to_string();
                                        let sign =
                                            j.get("sign").map(|s| s.as_str().unwrap().to_string());
                                        let value =
                                            j.get("value").map(|s| s.as_str().unwrap().to_string());
                                        Code { code, sign, value }
                                    })
                                    .collect(),
                            )
                        });
                        DrivingPrivilege {
                            vehicle_category_code,
                            issue_date,
                            expiry_date,
                            codes,
                        }
                        .into()
                    })
                    .collect::<Vec<CborValue>>()
                    .into(),
            ),
        ]
        .into_iter()
        .collect();

        let aamva_namespace = String::from("org.iso.18013.5.1.aamva");
        let aamva_elements = [
            (
                "sex".to_string().into(),
                mdl_data
                    .get("org.iso.18013.5.1.aamva.sex")
                    .ok_or_else(|| anyhow!("missing required element: missing required element: org.iso.18013.5.1.aamva.sex"))?
                    .as_i64()
                    .ok_or_else(|| anyhow!("expected integer for element: org.iso.18013.5.1.aamva.sex"))?
                    .into(),
            ),
            (
                "given_name_truncation".to_string().into(),
                mdl_data
                    .get("org.iso.18013.5.1.aamva.given_name_truncation")
                    .ok_or_else(|| anyhow!("missing required element: missing required element: org.iso.18013.5.1.aamva.given_name_truncation"))?
                    .as_str()
                    .ok_or_else(|| anyhow!("expected string for element: org.iso.18013.5.1.aamva.given_name_truncation"))?
                    .to_string()
                    .into(),
            ),
            (
                "family_name_truncation".to_string().into(),
                mdl_data
                    .get("org.iso.18013.5.1.aamva.family_name_truncation")
                    .ok_or_else(|| anyhow!("missing required element: missing required element: org.iso.18013.5.1.aamva.family_name_truncation"))?
                    .as_str()
                    .ok_or_else(|| anyhow!("expected string for element: org.iso.18013.5.1.aamva.family_name_truncation"))?
                    .to_string()
                    .into(),
            ),
            (
                "aamva_version".to_string().into(),
                mdl_data
                    .get("org.iso.18013.5.1.aamva.aamva_version")
                    .ok_or_else(|| anyhow!("missing required element: missing required element: org.iso.18013.5.1.aamva.aamva_version"))?
                    .as_i64()
                    .ok_or_else(|| anyhow!("expected integer for element: org.iso.18013.5.1.aamva.aamva_version"))?
                    .into(),
            ),
            (
                "domestic_driving_privileges".to_string().into(),
                aamva::privileges_from_json(mdl_data.get_mut("org.iso.18013.5.1.aamva.domestic_driving_privileges")
                    .ok_or_else(|| anyhow!("missing required element: missing required element: org.iso.18013.5.1.aamva.domestic_driving_privileges"))?.take())?
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<CborValue>>()
                    .into(),
            ),
        ]
        .into_iter()
        .collect();

        let namespaces = [
            (isomdl_namespace.clone(), isomdl_elements),
            (aamva_namespace.clone(), aamva_elements),
        ]
        .into_iter()
        .collect();

        let x5chain = X5Chain::builder()
            .with_pem(ISSUER_CERT)
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

        let approved_namespaces = vec![isomdl_namespace, aamva_namespace];
        let device_key_info = DeviceKeyInfo {
            device_key,
            key_authorizations: Some(KeyAuthorizations {
                namespaces: NonEmptyVec::maybe_new(approved_namespaces),
                data_elements: None,
            }),
            key_info: None,
        };

        let signer: p256::ecdsa::SigningKey = p256::SecretKey::from_pkcs8_pem(ISSUER_KEY)
            .expect("failed to parse pem")
            .into();

        let mdoc = Mdoc::builder()
            .doc_type(doc_type)
            .namespaces(namespaces)
            .x5chain(x5chain)
            .validity_info(validity_info)
            .digest_algorithm(digest_algorithm)
            .device_key_info(device_key_info)
            .issue(signer)
            .expect("failed to issue mdoc");

        Ok(mdoc)
    }
}
