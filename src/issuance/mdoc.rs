use std::collections::{BTreeMap, HashSet};

use anyhow::{anyhow, Result};
use async_signature::AsyncSigner;
use coset::iana::Algorithm;
use coset::{CoseSign1, Label};
use rand::Rng;
use serde::{Deserialize, Serialize};
use signature::{SignatureEncoding, Signer};

use crate::cose::sign1::PreparedCoseSign1;
use crate::cose::{MaybeTagged, SignatureAlgorithm};
use crate::{
    definitions::x509::x5chain::{X5Chain, X5CHAIN_COSE_HEADER_LABEL},
    definitions::{
        helpers::{NonEmptyMap, NonEmptyVec, Tag24},
        issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes},
        DeviceKeyInfo, DigestAlgorithm, DigestId, DigestIds, IssuerSignedItem, Mso, ValidityInfo,
    },
};

pub type Namespaces = BTreeMap<String, BTreeMap<String, ciborium::Value>>;

/// A signed mdoc.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Mdoc {
    pub doc_type: String,
    pub mso: Mso,
    pub namespaces: IssuerNamespaces,
    pub issuer_auth: MaybeTagged<CoseSign1>,
}

/// An incomplete mdoc, requiring a remotely signed signature to be completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        signature_algorithm: Algorithm,
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

        let mso_bytes = crate::cbor::to_vec(&Tag24::new(&mso)?)?;

        let protected = coset::HeaderBuilder::new()
            .algorithm(signature_algorithm)
            .build();
        let builder = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(mso_bytes);
        let prepared_sig = PreparedCoseSign1::new(builder, None, None, false)?;

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
            .push((Label::Int(X5CHAIN_COSE_HEADER_LABEL), x5chain.into_cbor()));
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
                .map(|elems| (name, elems))
        })
        .collect::<Result<BTreeMap<String, NonEmptyVec<Tag24<IssuerSignedItem>>>>>()
        .and_then(|namespaces| {
            NonEmptyMap::try_from(namespaces)
                .map_err(|_| anyhow!("at least one namespace required"))
        })
}

fn to_issuer_signed_items(
    elements: BTreeMap<String, ciborium::Value>,
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
                name.clone(),
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
        .map(|item| Ok((item.as_ref().digest_id, crate::cbor::to_vec(item)?)))
        .chain(random_digests)
        .map(|result| {
            let (digest_id, bytes) = result?;
            let digest = digest_algorithm.digest(&bytes);
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
#[path = "mdoc_tests.rs"]
pub mod test;
