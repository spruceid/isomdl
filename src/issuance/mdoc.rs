use crate::{
    definitions::{
        device_key::Error as KeyAuthError,
        helpers::{NonEmptyMap, NonEmptyVec, Tag24},
        issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes},
        validity_info::{Builder as ValidityInfoBuilder, BuilderError as ValidityBuilderError},
        CoseKey, DeviceKeyInfo, DigestAlgorithm, DigestId, DigestIds, IssuerSignedItem,
        KeyAuthorizations, Mso, ValidityInfo,
    },
    issuance::x5chain::{X5Chain, X5CHAIN_HEADER_LABEL},
};
use anyhow::{anyhow, Result};
use aws_nitro_enclaves_cose::{
    crypto::{Openssl, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey},
    header_map::HeaderMap,
    CoseSign1,
};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_cbor::{Error as CborError, Value as CborValue};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{HashMap, HashSet};

pub type Namespaces = HashMap<String, HashMap<String, CborValue>>;

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
}

#[derive(Debug, Default)]
pub struct Builder {
    device_key: Option<CoseKey>,
    doc_type: Option<String>,
    digest_algorithm: Option<DigestAlgorithm>,
    key_auth: KeyAuthorizations,
    key_info: HashMap<i128, CborValue>,
    namespaces: Namespaces,
    validity_info: ValidityInfoBuilder,
}

#[derive(Debug, thiserror::Error)]
pub enum PreparationError {
    #[error("missing required parameter: device_key")]
    DeviceKey,
    #[error("missing required parameter: digest_algorithm")]
    DigestAlgorithm,
    #[error("missing required parameter: doc_type")]
    DocType,
    #[error("integer supplied for label is in the range of values that are reserved for future use (RFU)")]
    LabelRFU,
    #[error("at least one data element is required in each namespace")]
    EmptyNamespace,
    #[error("at least one namespace of data elements is required")]
    NoNamespaces,
    #[error("{0}")]
    Other(String),
    #[error("unable to encode the value as cbor: {0}")]
    Cbor(#[from] CborError),
    #[error(transparent)]
    KeyAuth(#[from] KeyAuthError),
    #[error(transparent)]
    ValidityBuilder(#[from] ValidityBuilderError),
}

impl Mdoc {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn prepare_mdoc(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
    ) -> Result<MdocPreparation, PreparationError> {
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
        };

        Ok(preparation_mdoc)
    }

    pub fn issue<T: SigningPrivateKey + SigningPublicKey>(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        x5chain: X5Chain,
        signer: T,
    ) -> Result<Mdoc> {
        Self::prepare_mdoc(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
        )?
        .complete(signer, x5chain)
    }
}

impl MdocPreparation {
    pub fn complete<T: SigningPrivateKey + SigningPublicKey>(
        self,
        signer: T,
        x5chain: X5Chain,
    ) -> Result<Mdoc> {
        let MdocPreparation {
            doc_type,
            namespaces,
            mso,
        } = self;

        let signer_algorithm = signer
            .get_parameters()
            .map_err(|error| anyhow!("error getting signer parameters: {error}"))?
            .0;

        // Should/can we assert that the signer is the key identified by the x5chain?
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

        // headermap should contain alg header and x5chain header
        let protected_headers: HeaderMap = signer_algorithm.into();

        let mut unprotected_headers = HeaderMap::new();
        unprotected_headers.insert(
            serde_cbor::Value::Integer(X5CHAIN_HEADER_LABEL),
            x5chain.into_cbor()?,
        );

        let cose_sign1 = CoseSign1::new_with_protected::<Openssl>(
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

fn to_issuer_namespaces(namespaces: Namespaces) -> Result<IssuerNamespaces, PreparationError> {
    namespaces
        .into_iter()
        .map(|(name, elements)| {
            to_issuer_signed_items(elements)
                .map(Tag24::new)
                .collect::<Result<Vec<Tag24<IssuerSignedItem>>, _>>()
                .map_err(|err| format!("unable to encode IssuerSignedItem as cbor: {}", err))
                .map_err(PreparationError::Other)
                .and_then(|items| {
                    NonEmptyVec::try_from(items).map_err(|_| PreparationError::EmptyNamespace)
                })
                .map(|elems| (name, elems))
        })
        .collect::<Result<HashMap<_, _>, _>>()
        .and_then(|namespaces| {
            NonEmptyMap::try_from(namespaces).map_err(|_| PreparationError::NoNamespaces)
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
) -> Result<HashMap<String, DigestIds>, PreparationError> {
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
        .map(Result::<_, PreparationError>::Ok)
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

impl Builder {
    /// Timestamp that the mdoc will be signed at.
    pub fn signed_at(mut self, dt: DateTime<Utc>) -> Self {
        self.validity_info = self.validity_info.signed_at(dt);
        self
    }

    /// Timestamp that the mdoc will be valid from.
    pub fn valid_from(mut self, dt: DateTime<Utc>) -> Self {
        self.validity_info = self.validity_info.valid_from(dt);
        self
    }

    /// Timestamp that the mdoc will be valid until.
    pub fn valid_until(mut self, dt: DateTime<Utc>) -> Self {
        self.validity_info = self.validity_info.valid_until(dt);
        self
    }

    /// Timestamp at which the issuing authority expects to re-sign the MSO.
    pub fn expected_update_at(mut self, dt: DateTime<Utc>) -> Self {
        self.validity_info = self.validity_info.expected_update_at(dt);
        self
    }

    /// COSE_Key that the mdoc will use for authentication.
    pub fn with_device_key(mut self, device_key: CoseKey) -> Self {
        self.device_key = Some(device_key);
        self
    }

    /// Document type, for example `"org.iso.18013.5.1.mDL".`.
    pub fn with_doc_type(mut self, doc_type: String) -> Self {
        self.doc_type = Some(doc_type);
        self
    }

    /// Algorithm used to create element digests.
    pub fn with_digest_algorithm(mut self, digest_algorithm: DigestAlgorithm) -> Self {
        self.digest_algorithm = Some(digest_algorithm);
        self
    }

    /// Additional information about the device key.
    ///
    /// # Errors
    /// Positive integers are RFU for the label, therefore this function will error if a positive
    /// label is received.
    pub fn with_additional_device_key_info(
        mut self,
        label: i128,
        value: CborValue,
    ) -> Result<Self, PreparationError> {
        if label >= 0 {
            return Err(PreparationError::LabelRFU);
        }
        self.key_info.insert(label, value);
        Ok(self)
    }

    /// Data elements to be issued under the supplied namespace.
    ///
    /// Data elements are not merged, therefore if there are existing data elements for the
    /// supplied namespace, then they will be replaced with the incoming elements.
    pub fn with_namespace(
        mut self,
        namespace: String,
        data_elements: HashMap<String, CborValue>,
    ) -> Self {
        self.namespaces.insert(namespace, data_elements);
        self
    }

    /// Authorize the device key to calculate a signature or MAC over all data elements in a
    /// namespace.
    pub fn authorize_namespace(mut self, namespace: String) -> Self {
        if let Some(namespaces) = self.key_auth.namespaces.as_mut() {
            namespaces.push(namespace);
        } else {
            self.key_auth.namespaces = Some(NonEmptyVec::new(namespace));
        }
        self
    }

    /// Authorize the device key to calculate a signature or MAC over a particular data element.
    pub fn authorize_element(mut self, namespace: String, element: String) -> Self {
        if let Some(namespaces) = self.key_auth.data_elements.as_mut() {
            if let Some(elements) = namespaces.get_mut(&namespace) {
                elements.push(element)
            }
        } else {
            self.key_auth.data_elements =
                Some(NonEmptyMap::new(namespace, NonEmptyVec::new(element)));
        }
        self
    }

    pub fn prepare(self) -> Result<MdocPreparation, PreparationError> {
        let doc_type = self.doc_type.ok_or(PreparationError::DocType)?;

        let validity_info = self.validity_info.build()?;

        let digest_algorithm = self
            .digest_algorithm
            .ok_or(PreparationError::DigestAlgorithm)?;

        let device_key = self.device_key.ok_or(PreparationError::DeviceKey)?;
        self.key_auth.validate()?;
        let key_authorizations = if self.key_auth.is_empty() {
            None
        } else {
            Some(self.key_auth)
        };
        let key_info = if self.key_info.is_empty() {
            None
        } else {
            Some(self.key_info)
        };
        let device_key_info = DeviceKeyInfo {
            device_key,
            key_authorizations,
            key_info,
        };

        Mdoc::prepare_mdoc(
            doc_type,
            self.namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
        )
    }

    pub fn issue<S: SigningPublicKey + SigningPrivateKey>(
        self,
        signer: S,
        x5chain: X5Chain,
    ) -> Result<Mdoc> {
        self.prepare()?.complete(signer, x5chain)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::FromHex;
    use time::OffsetDateTime;

    static ISSUER_CERT: &[u8] = include_bytes!("../../test/issuance/256-cert.pem");
    static ISSUER_KEY: &[u8] = include_bytes!("../../test/issuance/256-key.pem");
    static COSE_KEY: &str = include_str!("../../test/definitions/cose_key/ec_p256.cbor");

    #[test]
    fn issue_minimal_mdoc() {
        let doc_type = String::from("org.iso.18013.5.1.mDL");

        let mdl_namespace = String::from("org.iso.18013.5.1");
        let mdl_elements = [("family_name".into(), "Smith".to_string().into())]
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

        let device_key_bytes =
            <Vec<u8>>::from_hex(COSE_KEY).expect("unable to convert cbor hex to bytes");
        let device_key = serde_cbor::from_slice(&device_key_bytes).unwrap();

        let now = std::time::SystemTime::now();
        let until = now + std::time::Duration::from_secs(3600);

        let signer = openssl::pkey::PKey::private_key_from_pem(ISSUER_KEY).unwrap();

        let x5chain = X5Chain::builder()
            .with_pem(ISSUER_CERT)
            .unwrap()
            .build()
            .unwrap();

        Mdoc::builder()
            .with_doc_type(doc_type)
            .with_namespace(mdl_namespace.clone(), mdl_elements)
            .with_digest_algorithm(DigestAlgorithm::SHA256)
            .with_device_key(device_key)
            .authorize_namespace(mdl_namespace)
            .valid_from(now.clone().into())
            .signed_at(now.into())
            .valid_until(until.into())
            .issue(signer, x5chain)
            .expect("failed to issue mdoc");
    }
}
