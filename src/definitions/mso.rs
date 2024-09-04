//! This module contains the definitions for the `MSO` (Mobile Security Object) structure.
//!
//! The `MSO structure represents a mobile security object, which is used in cryptographic operations
//! within the system. It contains information such as the version, digest algorithm, value digests,
//! device key info, document type, and validity info.
//!
//! # Examples
//!
//! ```ignore
//! use spruceid::definitions::mso::{Mso, DigestAlgorithm};
//! use std::collections::BTreeMap;
//!
//! // Create a new MSO object
//! let mso = Mso {
//!     version: String::from("1.0"),
//!     digest_algorithm: DigestAlgorithm::SHA256,
//!     value_digests: BTreeMap::new(),
//!     device_key_info: Default::default(),
//!     doc_type: String::from("document"),
//!     validity_info: Default::default(),
//! };
//!
//! // Print the MSO object
//! println!("{:?}", mso);
//! ```
//!
//! # Notes
//!
//! - [DigestId] struct represents an unsigned integer between `0` and `(2^31 - 1)` inclusive.  
//!   It is enforced to be positive.
//! - [DigestIds] type is a [BTreeMap] that maps [DigestId] to [ByteStr].
//! - [DigestAlgorithm] enum represents different digest algorithms, such as `SHA-256, `SHA-384,
//!   and `SHA-512`.
use crate::cbor::CborValue;
use crate::definitions::{helpers::ByteStr, DeviceKeyInfo, ValidityInfo};
use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use isomdl_macros::FieldsNames;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub enum Error {
    Deserialize(&'static str),
}

/// DigestId is a unsigned integer between `0` and `(2^31 - 1)` inclusive.
/// Therefore, the most straightforward way to represent it is as an i32 that is enforced to be
/// positive.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd, Copy, Hash)]
pub struct DigestId(pub(crate) i32);
pub type DigestIds = BTreeMap<DigestId, ByteStr>;

impl From<DigestIds> for CborValue {
    fn from(value: DigestIds) -> Self {
        CborValue::Map(
            value
                .into_iter()
                .map(|(k, v)| (CborValue::Integer(k.0 as i128), v.into()))
                .collect::<BTreeMap<CborValue, CborValue>>(),
        )
    }
}

impl TryFrom<CborValue> for DigestIds {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_map()
            .map_err(|_| Error::Deserialize("not an map"))?
            .into_iter()
            .map(|(k, v)| {
                let k = k
                    .into_integer()
                    .map_err(|_| Error::Deserialize("cannot deserialize key"))?;
                let v = ByteStr::try_from(v)
                    .map_err(|_| Error::Deserialize("cannot deserialize value"))?;
                Ok((DigestId(k as i32), v))
            })
            .collect::<Result<BTreeMap<DigestId, ByteStr>, Error>>()
    }
}

/// Represents an [Mso] object.
#[derive(Clone, Debug, FieldsNames)]
#[isomdl(rename_all = "camelCase")]
pub struct Mso {
    /// The version of the Mso object.
    pub version: String,

    /// The digest algorithm used by the Mso object.
    pub digest_algorithm: DigestAlgorithm,

    /// A map of value digests associated with their respective digest IDs.
    pub value_digests: BTreeMap<String, DigestIds>,

    /// Information about the device key used by the Mso object.
    pub device_key_info: DeviceKeyInfo,

    /// The document type associated with the Mso object.
    pub doc_type: String,

    /// Information about the validity of the Mso object.
    pub validity_info: ValidityInfo,
}

impl CborSerializable for Mso {}
impl AsCborValue for Mso {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "Mso is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(Mso {
            version: map
                .remove(&Mso::fn_version().into())
                .ok_or_else(|| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "version not found".to_string(),
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "version cannot be converted".to_string(),
                    ))
                })?,
            digest_algorithm: match map
                .remove(&Mso::fn_digest_algorithm().into())
                .ok_or_else(|| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "digest_algorithm not found".to_string(),
                    ))
                })?
                .into_integer()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "digest_algorithm is not an integer".to_string(),
                    ))
                })? {
                1 => DigestAlgorithm::SHA256,
                2 => DigestAlgorithm::SHA384,
                3 => DigestAlgorithm::SHA512,
                _ => {
                    return Err(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "digest_algorithm is not an integer".to_string(),
                        ),
                    ))
                }
            },
            value_digests: map
                .remove(&Mso::fn_value_digests().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "value_digests is missing".to_string()),
                ))?
                .into_map()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "value_digests is not a map".to_string(),
                    ))
                })?
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k.into_text().map_err(|_| {
                            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                None,
                                "value_digests key is not a string".to_string(),
                            ))
                        })?,
                        v.into_map()
                            .map_err(|_| {
                                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                    None,
                                    "value_digests is not an map".to_string(),
                                ))
                            })?
                            .into_iter()
                            .map(|(k, v)| {
                                Ok((
                                    DigestId(k.into_integer().map_err(|_| {
                                        coset::CoseError::DecodeFailed(
                                            ciborium::de::Error::Semantic(
                                                None,
                                                "value_digests DigestIds is not an integer"
                                                    .to_string(),
                                            ),
                                        )
                                    })? as i32),
                                    v.try_into().map_err(|_| {
                                        coset::CoseError::DecodeFailed(
                                            ciborium::de::Error::Semantic(
                                                None,
                                                "value_digests DigestIds is not an ByteStr"
                                                    .to_string(),
                                            ),
                                        )
                                    })?,
                                ))
                            })
                            .collect::<coset::Result<DigestIds>>()?,
                    ))
                })
                .collect::<coset::Result<BTreeMap<String, DigestIds>>>()?,
            device_key_info: DeviceKeyInfo::from_cbor_value(
                map.remove(&Mso::fn_device_key_info().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "device_key_info not found".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            doc_type: map
                .remove(&Mso::fn_doc_type().into())
                .ok_or_else(|| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "doc_type not found".to_string(),
                    ))
                })?
                .into_text()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "doc_type cannot be converted".to_string(),
                    ))
                })?,
            validity_info: ValidityInfo::from_cbor_value(
                map.remove(&Mso::fn_validity_info().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, "validity_info not found".to_string()),
                    ))?
                    .into(),
            )?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![];
        map.push((
            Value::Text(Mso::fn_version().to_string()),
            Value::Text(self.version),
        ));
        map.push((
            Mso::fn_digest_algorithm().into(),
            match self.digest_algorithm {
                DigestAlgorithm::SHA256 => 1.into(),
                DigestAlgorithm::SHA384 => 2.into(),
                DigestAlgorithm::SHA512 => 3.into(),
            },
        ));
        map.push((
            Mso::fn_value_digests().into(),
            Value::Map(
                self.value_digests
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            Value::Text(k),
                            Value::Map(
                                v.into_iter()
                                    .map(|(k, v)| (Value::Integer(k.0.into()), v.into()))
                                    .collect(),
                            ),
                        )
                    })
                    .collect(),
            ),
        ));
        map.push((
            Value::Text(Mso::fn_device_key_info().to_string()),
            self.device_key_info.to_cbor_value()?,
        ));
        map.push((
            Value::Text(Mso::fn_doc_type().to_string()),
            Value::Text(self.doc_type),
        ));
        map.push((
            Value::Text(Mso::fn_validity_info().to_string()),
            self.validity_info.to_cbor_value()?,
        ));
        Ok(Value::Map(map))
    }
}

#[derive(Clone, Debug, Copy, Deserialize, Serialize)]
pub enum DigestAlgorithm {
    SHA256,
    SHA384,
    SHA512,
}

impl DigestId {
    pub fn new(i: i32) -> DigestId {
        DigestId(if i.is_negative() { -i } else { i })
    }
}

#[cfg(test)]
mod test {
    use crate::definitions::{helpers::Tag24, IssuerSigned, Mso};
    use coset::CborSerializable;
    use hex::FromHex;

    static ISSUER_SIGNED_CBOR: &str = include_str!("../../test/definitions/issuer_signed.cbor");

    #[test]
    fn serde_mso() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(ISSUER_SIGNED_CBOR).expect("unable to convert cbor hex to bytes");
        let signed = IssuerSigned::from_slice(&cbor_bytes)
            .expect("unable to decode cbor as an IssuerSigned");
        let mso_bytes = signed
            .issuer_auth
            .inner
            .payload
            .as_ref()
            .expect("expected a COSE_Sign1 with attached payload, found detached payload");
        let mso = Tag24::<Mso>::from_slice(mso_bytes).expect("unable to parse payload as Mso");
        let roundtripped_bytes = mso.to_vec().expect("unable to encode Mso as cbor bytes");
        assert_eq!(
            mso_bytes, &roundtripped_bytes,
            "original cbor and re-serialized Mso do not match"
        )
    }
}
