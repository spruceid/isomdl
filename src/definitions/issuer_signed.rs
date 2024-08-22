//! This module contains the definition of the [IssuerSigned] struct and related types.
//!
//! The [IssuerSigned] struct represents a signed issuer object, which includes information about `namespaces`, `authentication`, and `signed items`.
//!
//! # Notes
//!
//! - [IssuerSigned] struct is serialized and deserialized using the [Serialize] and [Deserialize] traits from the [serde] crate.
//! - [IssuerNamespaces] type is an alias for [`NonEmptyMap<String, NonEmptyVec<IssuerSignedItemBytes>>`].
//! - [IssuerSignedItemBytes] type is an alias for [`Tag24<IssuerSignedItem>`].
//! - [IssuerSignedItem] struct represents a signed item within the [IssuerSigned] object, including information such as digest ID, random bytes, element identifier, and element value.
//! - [IssuerSigned] struct also includes a test module with a unit test for serialization and deserialization.
use crate::cose;
use crate::cose::sign1::CoseSign1;
use crate::definitions::{
    helpers::{non_empty_map, ByteStr, NonEmptyMap, NonEmptyVec, Tag24},
    DigestId,
};
use coset::AsCborValue;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;

/// Represents an issuer-signed object.
///
/// This struct is used to store information about an issuer-signed object, which includes namespaces and issuer authentication.
/// [IssuerSigned::namespaces] field is an optional [IssuerNamespaces] object that contains namespaces associated with the issuer.
/// [IssuerSigned::issuer_auth] field is a [CoseSign1] object that represents the issuer authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    #[serde(skip_serializing_if = "Option::is_none", rename = "nameSpaces")]
    pub namespaces: Option<IssuerNamespaces>,
    pub issuer_auth: CoseSign1,
}

pub type IssuerNamespaces = NonEmptyMap<String, NonEmptyVec<IssuerSignedItemBytes>>;
pub type IssuerSignedItemBytes = Tag24<IssuerSignedItem>;

/// Represents an item signed by the issuer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    /// The ID of the digest used for signing.
    #[serde(rename = "digestID")]
    pub digest_id: DigestId,

    /// Random bytes associated with the signed item.
    pub random: ByteStr,

    /// The identifier of the element.
    pub element_identifier: String,

    /// The value of the element.
    pub element_value: CborValue,
}

impl coset::CborSerializable for IssuerSignedItem {}
impl AsCborValue for IssuerSignedItem {
    fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
        let mut arr = if let ciborium::Value::Array(arr) = value {
            arr
        } else {
            return Err(coset::CoseError::UnexpectedItem(
                "value",
                "array for IssuerSignedItem",
            ));
        };
        Ok(IssuerSignedItem {
            digest_id: DigestId::new(if let ciborium::Value::Integer(i) = arr.remove(0) {
                i.try_into()?
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "integer for for DigestId",
                ));
            }),
            random: ByteStr::from(if let ciborium::Value::Bytes(b) = &arr.remove(0) {
                b.to_vec()
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "bytes for for ByteStr",
                ));
            }),
            element_identifier: if let ciborium::Value::Text(s) = &arr.remove(0) {
                s.clone()
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "bytes for for ByteStr",
                ));
            },
            element_value: cose::ciborium_value_into_serde_cbor_value(arr.remove(0))?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
        Ok(ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("digestID".to_string()),
                ciborium::Value::Integer(self.digest_id.0.into()),
            ),
            (
                ciborium::Value::Text("random".to_string()),
                ciborium::Value::Bytes(self.random.into()),
            ),
            (
                ciborium::Value::Text("elementIdentifier".to_string()),
                ciborium::Value::Text(self.element_identifier),
            ),
            (
                ciborium::Value::Text("elementValue".to_string()),
                cose::serde_cbor_value_into_ciborium_value(self.element_value)?,
            ),
        ]))
    }
}

impl coset::CborSerializable for IssuerSigned {}
impl AsCborValue for IssuerSigned {
    fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
        if let ciborium::Value::Array(mut arr) = value {
            if arr.len() > 2 {
                return Err(coset::CoseError::ExtraneousData);
            } else if arr.is_empty() {
                return Err(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "missing data".to_string()),
                ));
            }
            let namespaces = if arr.len() >= 2 {
                Some(arr.remove(0))
            } else {
                None
            };
            let namespaces: Option<IssuerNamespaces> =
                namespaces.map(non_empty_map::from_cbor_value).transpose()?;
            let issuer_auth = CoseSign1::from_cbor_value(arr.remove(0)).map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "invalid CoseSign1".to_string(),
                ))
            })?;
            Ok(IssuerSigned {
                namespaces,
                issuer_auth,
            })
        } else {
            Err(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "not an array".to_string()),
            ))
        }
    }

    fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
        let mut arr = vec![];
        if let Some(namespaces) = self.namespaces {
            arr.push(non_empty_map::to_cbor_value(namespaces)?)
        }
        arr.push(self.issuer_auth.to_cbor_value()?);
        Ok(ciborium::Value::Array(arr))
    }
}

#[cfg(test)]
mod test {
    use super::IssuerSigned;
    use hex::FromHex;

    static ISSUER_SIGNED_CBOR: &str = include_str!("../../test/definitions/issuer_signed.cbor");

    #[test]
    fn serde_issuer_signed() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(ISSUER_SIGNED_CBOR).expect("unable to convert cbor hex to bytes");
        let signed: IssuerSigned =
            serde_cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as an IssuerSigned");
        let roundtripped_bytes =
            serde_cbor::to_vec(&signed).expect("unable to encode IssuerSigned as cbor bytes");
        assert_eq!(
            cbor_bytes, roundtripped_bytes,
            "original cbor and re-serialized IssuerSigned do not match"
        );
    }
}
