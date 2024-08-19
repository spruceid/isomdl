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
use crate::cose::sign1::CoseSign1;
use crate::definitions::{
    helpers::{ByteStr, NonEmptyMap, NonEmptyVec, Tag24},
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
        let arr = if let ciborium::Value::Array(arr) = value {
            arr
        } else {
            return Err(coset::CoseError::UnexpectedItem(
                "value",
                "array for IssuerSignedItem",
            ));
        };
        Ok(IssuerSignedItem {
            digest_id: DigestId::new(if let ciborium::Value::Integer(i) = arr[0] {
                i.try_into()?
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "integer for for DigestId",
                ));
            }),
            random: ByteStr::from(if let ciborium::Value::Bytes(b) = &arr[1] {
                b.to_vec()
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "bytes for for ByteStr",
                ));
            }),
            element_identifier: if let ciborium::Value::Text(s) = &arr[2] {
                s.clone()
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "bytes for for ByteStr",
                ));
            },
            element_value: ciborium_value_into_cbor_value(&arr[3])?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
        Ok(ciborium::Value::Array(vec![
            ciborium::Value::Integer(self.digest_id.0.into()),
            ciborium::Value::Bytes(self.random.into()),
            ciborium::Value::Text(self.element_identifier),
            cbor_value_into_ciborium_value(self.element_value)?,
        ]))
    }
}

impl coset::CborSerializable for IssuerSigned {}
impl AsCborValue for IssuerSigned {
    fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
        let arr = vec![];
        if let ciborium::Value::Array(arr) = value {
            let namespaces = arr.get(0).map(|v| v.clone());
            let issuer_auth = arr.get(1).map(|v| v.clone());
            Ok(IssuerSigned {
                namespaces,
                issuer_auth,
            })
        } else {
            Err(coset::Error::Custom("Invalid IssuerSigned".to_string()))
        }
    }

    fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
        let arr = vec![];
        if let Some(namespaces) = self.namespaces {
            arr.push(ciborium::Value::Map(
                namespaces
                    .into_iter()
                    .map(|s| {
                        let (k, v) = s;
                        let k = ciborium::Value::Text(k);
                        let v = v.into_iter().map(|i| i.to_cbor_value()).collect();
                        (k, v.into_iter().map(|i| i.to_cbor_value()).collect())
                    })
                    .collect(),
            ))
        }
        arr.push(self.issuer_auth.to_cbor_value()?);
        Ok(ciborium::Value::Array(arr))
    }
}

fn cbor_value_into_ciborium_value(val: CborValue) -> coset::Result<ciborium::Value> {
    match val {
        CborValue::Null => Ok(ciborium::Value::Null),
        CborValue::Bool(b) => Ok(ciborium::Value::Bool(b)),
        CborValue::Integer(i) => Ok(ciborium::Value::Integer(i.try_into()?)),
        CborValue::Float(f) => Ok(ciborium::Value::Float(f)),
        CborValue::Bytes(b) => Ok(ciborium::Value::Bytes(b)),
        CborValue::Text(t) => Ok(ciborium::Value::Text(t)),
        CborValue::Array(a) => Ok(ciborium::Value::Array(
            a.into_iter()
                .map(cbor_value_into_ciborium_value)
                .flatten()
                .collect(),
        )),
        CborValue::Map(m) => Ok(ciborium::Value::Map(
            m.into_iter()
                .map(|(k, v)| {
                    Ok::<(ciborium::Value, ciborium::Value), coset::CoseError>((
                        cbor_value_into_ciborium_value(k)?,
                        cbor_value_into_ciborium_value(v)?,
                    ))
                })
                .flatten()
                .collect(),
        )),
        CborValue::Tag(t, v) => Ok(ciborium::Value::Tag(
            t,
            Box::new(cbor_value_into_ciborium_value(*v)?),
        )),
        _ => unimplemented!("Unsupported cbor value {val:?}"),
    }
}

fn ciborium_value_into_cbor_value(val: &ciborium::Value) -> coset::Result<CborValue> {
    match val {
        ciborium::Value::Null => Ok(CborValue::Null),
        ciborium::Value::Bool(b) => Ok(CborValue::Bool(*b)),
        ciborium::Value::Integer(i) => Ok(CborValue::Integer((*i).into())),
        ciborium::Value::Float(f) => Ok(CborValue::Float(*f)),
        ciborium::Value::Bytes(b) => Ok(CborValue::Bytes(*b)),
        ciborium::Value::Text(t) => Ok(CborValue::Text(*t)),
        ciborium::Value::Array(a) => Ok(CborValue::Array(
            a.into_iter()
                .map(ciborium_value_into_cbor_value)
                .flatten()
                .collect(),
        )),
        ciborium::Value::Map(m) => Ok(CborValue::Map(
            m.into_iter()
                .map(|(k, v)| {
                    Ok::<(CborValue, CborValue), coset::CoseError>((
                        ciborium_value_into_cbor_value(k)?,
                        ciborium_value_into_cbor_value(v)?,
                    ))
                })
                .flatten()
                .collect(),
        )),
        ciborium::Value::Tag(t, v) => Ok(CborValue::Tag(
            *t,
            Box::new(ciborium_value_into_cbor_value(v)?),
        )),
        _ => unimplemented!("Unsupported cbor value {val:?}"),
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
