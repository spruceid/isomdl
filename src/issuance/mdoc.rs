use std::collections::{BTreeMap, HashSet};

use crate::cose::CborValue;
use anyhow::{anyhow, Result};
use async_signature::AsyncSigner;
use coset::{iana, Label};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{SignatureEncoding, Signer};

use crate::cose::sign1::{CoseSign1, PreparedCoseSign1};
use crate::cose::SignatureAlgorithm;
use crate::definitions::helpers::string_cbor::CborString;
use crate::{
    definitions::{
        helpers::{NonEmptyMap, NonEmptyVec, Tag24},
        issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes},
        DeviceKeyInfo, DigestAlgorithm, DigestId, DigestIds, IssuerSignedItem, Mso, ValidityInfo,
    },
    issuance::x5chain::{X5Chain, X5CHAIN_HEADER_LABEL},
};

pub type Namespaces = BTreeMap<String, BTreeMap<String, CborValue>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// A signed mdoc.
pub struct Mdoc {
    pub doc_type: String,
    pub mso: Mso,
    pub namespaces: IssuerNamespaces,
    pub issuer_auth: CoseSign1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    enable_decoy_digests: Option<bool>,
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
        signature_algorithm: iana::Algorithm,
        enable_decoy_digests: bool,
    ) -> Result<PreparedMdoc> {
        if let Some(authorizations) = &device_key_info.key_authorizations {
            authorizations.validate()?;
        }

        let issuer_namespaces = to_issuer_namespaces(namespaces)?;
        let value_digests =
            digest_namespaces(&issuer_namespaces, digest_algorithm, enable_decoy_digests)?;

        let mso = Mso {
            version: "1.0".to_string(),
            digest_algorithm,
            value_digests,
            device_key_info,
            doc_type: doc_type.clone(),
            validity_info,
        };

        let mso_bytes = serde_cbor::to_vec(&Tag24::new(&mso)?)?;

        let protected = coset::HeaderBuilder::new()
            .algorithm(signature_algorithm)
            .build();
        let builder = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(mso_bytes);
        let prepared_sig = PreparedCoseSign1::new(builder, None, None, true)?;

        let preparation_mdoc = PreparedMdoc {
            doc_type,
            namespaces: issuer_namespaces,
            mso,
            prepared_sig,
        };

        Ok(preparation_mdoc)
    }

    /// Directly sign and issue an mdoc.
    #[allow(clippy::too_many_arguments)]
    pub fn issue<S, Sig>(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        x5chain: X5Chain,
        enable_decoy_digests: bool,
        signer: S,
    ) -> Result<Mdoc>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding,
    {
        let prepared_mdoc = Self::prepare(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            signer.algorithm(),
            enable_decoy_digests,
        )?;

        let signature_payload = prepared_mdoc.signature_payload();
        let signature = signer
            .try_sign(signature_payload)
            .map_err(|e| anyhow!("error signing cosesign1: {}", e))?
            .to_vec();

        Ok(prepared_mdoc.complete(x5chain, signature))
    }

    /// Directly sign and issue an mdoc.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_async<S, Sig>(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        x5chain: X5Chain,
        enable_decoy_digests: bool,
        signer: S,
    ) -> Result<Mdoc>
    where
        S: AsyncSigner<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding + Send + 'static,
    {
        let prepared_mdoc = Self::prepare(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            signer.algorithm(),
            enable_decoy_digests,
        )?;

        let signature_payload = prepared_mdoc.signature_payload();
        let signature = signer
            .sign_async(signature_payload)
            .await
            .map_err(|e| anyhow!("error signing cosesign1: {}", e))?
            .to_vec();

        Ok(prepared_mdoc.complete(x5chain, signature))
    }
}

impl PreparedMdoc {
    /// Retrieve the payload for a remote signature.
    pub fn signature_payload(&self) -> &[u8] {
        self.prepared_sig.signature_payload()
    }

    /// Supply the remotely signed signature and x5chain containing the issuing certificate
    /// to complete and issue the prepared mdoc.
    pub fn complete(self, x5chain: X5Chain, signature: Vec<u8>) -> Mdoc {
        let PreparedMdoc {
            doc_type,
            namespaces,
            mso,
            prepared_sig,
        } = self;

        let mut issuer_auth = prepared_sig.finalize(signature);
        issuer_auth
            .inner
            .unprotected
            .rest
            .push((Label::Int(X5CHAIN_HEADER_LABEL as i64), x5chain.into_cbor()));

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

    /// Enable the use of decoy digests.
    pub fn enable_decoy_digests(mut self, enable_decoy_digests: bool) -> Self {
        self.enable_decoy_digests = Some(enable_decoy_digests);
        self
    }

    /// Prepare the mdoc for remote signing.
    ///
    /// The signature algorithm which the mdoc will be signed with must be known ahead of time as
    /// it is a required field in the signature headers.
    pub fn prepare(self, signature_algorithm: iana::Algorithm) -> Result<PreparedMdoc> {
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
        let enable_decoy_digests = self.enable_decoy_digests.unwrap_or(true);

        Mdoc::prepare(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            signature_algorithm,
            enable_decoy_digests,
        )
    }

    /// Directly issue an mdoc.
    pub fn issue<S, Sig>(self, x5chain: X5Chain, signer: S) -> Result<Mdoc>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding,
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
        let enable_decoy_digests = self.enable_decoy_digests.unwrap_or(true);

        Mdoc::issue(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            x5chain,
            enable_decoy_digests,
            signer,
        )
    }

    /// Directly issue an mdoc.
    pub async fn issue_async<S, Sig>(self, x5chain: X5Chain, signer: S) -> Result<Mdoc>
    where
        S: AsyncSigner<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding + Send + 'static,
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
        let enable_decoy_digests = self.enable_decoy_digests.unwrap_or(true);

        Mdoc::issue_async(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            x5chain,
            enable_decoy_digests,
            signer,
        )
        .await
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
                .map(|elems| (CborString::from(name), elems))
        })
        .collect::<Result<BTreeMap<CborString, NonEmptyVec<Tag24<IssuerSignedItem>>>>>()
        .and_then(|namespaces| {
            NonEmptyMap::try_from(namespaces)
                .map_err(|_| anyhow!("at least one namespace required"))
        })
}

fn to_issuer_signed_items(
    elements: BTreeMap<String, CborValue>,
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
    enable_decoy_digests: bool,
) -> Result<BTreeMap<String, DigestIds>> {
    namespaces
        .iter()
        .map(|(name, elements)| {
            Ok((
                name.clone().into(),
                digest_namespace(elements, digest_algorithm, enable_decoy_digests)?,
            ))
        })
        .collect()
}

fn digest_namespace(
    elements: &[IssuerSignedItemBytes],
    digest_algorithm: DigestAlgorithm,
    enable_decoy_digests: bool,
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
        .take(if enable_decoy_digests {
            rand::thread_rng().gen_range(5..10)
        } else {
            0
        });

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
        digest_id = DigestId::new(rand::thread_rng().gen());
        if used_ids.insert(digest_id) {
            break;
        }
    }
    digest_id
}

#[cfg(test)]
pub mod test {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    use p256::SecretKey;
    use time::OffsetDateTime;

    use crate::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
    use crate::definitions::namespaces::{
        org_iso_18013_5_1::OrgIso1801351, org_iso_18013_5_1_aamva::OrgIso1801351Aamva,
    };
    use crate::definitions::traits::{FromJson, ToNamespaceMap};

    use super::*;

    static ISSUER_CERT: &[u8] = include_bytes!("../../test/issuance/issuer-cert.pem");
    static ISSUER_KEY: &str = include_str!("../../test/issuance/issuer-key.pem");

    fn isomdl_data() -> serde_json::Value {
        serde_json::json!(
            {
              "family_name":"Smith",
              "given_name":"Alice",
              "birth_date":"1980-01-01",
              "issue_date":"2020-01-01",
              "expiry_date":"2030-01-01",
              "issuing_country":"US",
              "issuing_authority":"NY DMV",
              "document_number":"DL12345678",
              "portrait":include_str!("../../test/issuance/portrait.b64"),
              "driving_privileges":[
                {
                   "vehicle_category_code":"A",
                   "issue_date":"2020-01-01",
                   "expiry_date":"2030-01-01"
                },
                {
                   "vehicle_category_code":"B",
                   "issue_date":"2020-01-01",
                   "expiry_date":"2030-01-01"
                }
              ],
              "un_distinguishing_sign":"USA",
              "administrative_number":"ABC123",
              "sex":1,
              "height":170,
              "weight":70,
              "eye_colour":"hazel",
              "hair_colour":"red",
              "birth_place":"Canada",
              "resident_address":"138 Eagle Street",
              "portrait_capture_date":"2020-01-01T12:00:00Z",
              "age_in_years":43,
              "age_birth_year":1980,
              "age_over_18":true,
              "age_over_21":true,
              "issuing_jurisdiction":"US-NY",
              "nationality":"US",
              "resident_city":"Albany",
              "resident_state":"New York",
              "resident_postal_code":"12202-1719",
              "resident_country": "US"
            }
        )
    }

    fn aamva_isomdl_data() -> serde_json::Value {
        serde_json::json!(
            {
              "domestic_driving_privileges":[
                {
                  "domestic_vehicle_class":{
                    "domestic_vehicle_class_code":"A",
                    "domestic_vehicle_class_description":"unknown",
                    "issue_date":"2020-01-01",
                    "expiry_date":"2030-01-01"
                  }
                },
                {
                  "domestic_vehicle_class":{
                    "domestic_vehicle_class_code":"B",
                    "domestic_vehicle_class_description":"unknown",
                    "issue_date":"2020-01-01",
                    "expiry_date":"2030-01-01"
                  }
                }
              ],
              "name_suffix":"1ST",
              "organ_donor":1,
              "veteran":1,
              "family_name_truncation":"N",
              "given_name_truncation":"N",
              "aka_family_name.v2":"Smithy",
              "aka_given_name.v2":"Ally",
              "aka_suffix":"I",
              "weight_range":3,
              "race_ethnicity":"AI",
              "EDL_credential":1,
              "sex":1,
              "DHS_compliance":"F",
              "resident_county":"001",
              "hazmat_endorsement_expiration_date":"2024-01-30",
              "CDL_indicator":1,
              "DHS_compliance_text":"Compliant",
              "DHS_temporary_lawful_status":1,
            }
        )
    }

    #[test]
    fn issue_minimal_mdoc() -> anyhow::Result<()> {
        minimal_test_mdoc()?;
        Ok(())
    }

    fn minimal_test_mdoc_builder() -> Builder {
        let doc_type = String::from("org.iso.18013.5.1.mDL");
        let isomdl_namespace = String::from("org.iso.18013.5.1");
        let aamva_namespace = String::from("org.iso.18013.5.1.aamva");

        let isomdl_data = OrgIso1801351::from_json(&isomdl_data())
            .unwrap()
            .to_ns_map();
        let aamva_data = OrgIso1801351Aamva::from_json(&aamva_isomdl_data())
            .unwrap()
            .to_ns_map();

        let namespaces = [
            (isomdl_namespace, isomdl_data),
            (aamva_namespace, aamva_data),
        ]
        .into_iter()
        .collect();

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

        let device_key_info = DeviceKeyInfo {
            device_key,
            key_authorizations: None,
            key_info: None,
        };

        Mdoc::builder()
            .doc_type(doc_type)
            .namespaces(namespaces)
            .validity_info(validity_info)
            .digest_algorithm(digest_algorithm)
            .device_key_info(device_key_info)
    }

    pub fn minimal_test_mdoc() -> anyhow::Result<Mdoc> {
        let mdoc_builder = minimal_test_mdoc_builder();

        let x5chain = X5Chain::builder()
            .with_pem(ISSUER_CERT)
            .unwrap()
            .build()
            .unwrap();
        let signer: SigningKey = SecretKey::from_pkcs8_pem(ISSUER_KEY)
            .expect("failed to parse pem")
            .into();

        Ok(mdoc_builder
            .issue::<SigningKey, Signature>(x5chain, signer)
            .expect("failed to issue mdoc"))
    }

    #[test]
    fn decoy_digests() {
        let mdoc_builder = minimal_test_mdoc_builder();
        let x5chain = X5Chain::builder()
            .with_pem(ISSUER_CERT)
            .unwrap()
            .build()
            .unwrap();
        let signer: SigningKey = SecretKey::from_pkcs8_pem(ISSUER_KEY)
            .expect("failed to parse pem")
            .into();

        let mdoc_decoy = &mdoc_builder
            .clone()
            .issue::<SigningKey, Signature>(x5chain.clone(), signer.clone())
            .unwrap();

        let mdoc_builder = mdoc_builder.enable_decoy_digests(false);
        let mdoc_no_decoy_1 = &mdoc_builder
            .clone()
            .issue::<SigningKey, Signature>(x5chain.clone(), signer.clone())
            .unwrap();
        let mdoc_no_decoy_2 = &mdoc_builder
            .issue::<SigningKey, Signature>(x5chain, signer)
            .unwrap();

        // Asserting on number of digests
        assert_eq!(
            mdoc_decoy
                .namespaces
                .values()
                .fold(0, |acc, x| acc + x.len()),
            mdoc_no_decoy_1
                .namespaces
                .values()
                .fold(0, |acc, x| acc + x.len()),
        );
        assert_ne!(
            mdoc_decoy
                .mso
                .value_digests
                .values()
                .fold(0, |acc, x| acc + x.len()),
            mdoc_no_decoy_1
                .mso
                .value_digests
                .values()
                .fold(0, |acc, x| acc + x.len()),
        );
        assert_eq!(
            mdoc_no_decoy_1
                .mso
                .value_digests
                .values()
                .fold(0, |acc, x| acc + x.len()),
            mdoc_no_decoy_2
                .mso
                .value_digests
                .values()
                .fold(0, |acc, x| acc + x.len()),
        );
    }
}
