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

use std::collections::HashMap;

use crate::cose::CborValue;
use ciborium::Value;
use coset::AsCborValue;
use isomdl_macros::FieldsNames;
use serde::{Deserialize, Serialize};

use crate::cose;
use crate::cose::sign1::CoseSign1;
use crate::definitions::helpers::string_cbor::CborString;
use crate::definitions::{
    helpers::{ByteStr, NonEmptyMap, NonEmptyVec, Tag24},
    DigestId,
};

/// Represents an issuer-signed object.
///
/// This struct is used to store information about an issuer-signed object, which includes namespaces and issuer authentication.
/// [IssuerSigned::namespaces] field is an optional [IssuerNamespaces] object that contains namespaces associated with the issuer.
/// [IssuerSigned::issuer_auth] field is a [CoseSign1] object that represents the issuer authentication.
#[derive(Clone, Debug, FieldsNames, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    #[serde(skip_serializing_if = "Option::is_none", rename = "nameSpaces")]
    pub namespaces: Option<IssuerNamespaces>,
    pub issuer_auth: CoseSign1,
}

pub type IssuerNamespaces = NonEmptyMap<CborString, NonEmptyVec<IssuerSignedItemBytes>>;
pub type IssuerSignedItemBytes = Tag24<IssuerSignedItem>;

/// Represents an item signed by the issuer.
#[derive(Clone, Debug, FieldsNames, Serialize, Deserialize)]
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
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut fields = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "IssuerSignedItem is not a map".to_string(),
                ))
            })?
            .into_iter()
            .flat_map(|f| match f.0 {
                Value::Text(s) => Ok::<(String, Value), coset::CoseError>((s, f.1)),
                _ => Err(coset::CoseError::UnexpectedItem(
                    "key",
                    "text for field in IssuerSignedItem",
                )),
            })
            .collect::<HashMap<String, Value>>();
        Ok(IssuerSignedItem {
            digest_id: DigestId::new(
                if let Some(Value::Integer(i)) = fields.remove(IssuerSignedItem::digest_id()) {
                    i.try_into()?
                } else {
                    return Err(coset::CoseError::UnexpectedItem(
                        "value",
                        "integer for for DigestId",
                    ));
                },
            ),
            random: ByteStr::from(
                if let Some(Value::Bytes(b)) = fields.remove(IssuerSignedItem::random()) {
                    b
                } else {
                    return Err(coset::CoseError::UnexpectedItem(
                        "value",
                        "bytes for for ByteStr",
                    ));
                },
            ),
            element_identifier: if let Some(Value::Text(s)) =
                fields.remove(IssuerSignedItem::element_identifier())
            {
                s.clone()
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "bytes for for ByteStr",
                ));
            },
            element_value: if let Some(element_value) =
                fields.remove(IssuerSignedItem::element_value())
            {
                cose::ciborium_value_into_serde_cbor_value(element_value)?
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "bytes for for CborValue",
                ));
            },
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(vec![
            (
                Value::Text(IssuerSignedItem::digest_id().to_string()),
                Value::Integer(self.digest_id.0.into()),
            ),
            (
                Value::Text(IssuerSignedItem::random().to_string()),
                Value::Bytes(self.random.into()),
            ),
            (
                Value::Text(IssuerSignedItem::element_identifier().to_string()),
                Value::Text(self.element_identifier),
            ),
            (
                Value::Text(IssuerSignedItem::element_value().to_string()),
                cose::serde_cbor_value_into_ciborium_value(self.element_value)?,
            ),
        ]))
    }
}

impl coset::CborSerializable for IssuerSigned {}
impl AsCborValue for IssuerSigned {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut fields = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "IssuerSigned is not a map".to_string(),
                ))
            })?
            .into_iter()
            .flat_map(|f| match f.0 {
                Value::Text(s) => Ok::<(CborString, Value), coset::CoseError>((s.into(), f.1)),
                _ => Err(coset::CoseError::UnexpectedItem(
                    "key",
                    "text for field in IssuerSigned",
                )),
            })
            .collect::<HashMap<CborString, Value>>();
        Ok(IssuerSigned {
            namespaces: if let Some(Value::Map(namespaces)) =
                fields.remove(&IssuerSigned::namespaces().into())
            {
                Some(NonEmptyMap::from_cbor_value(Value::Map(namespaces))?)
            } else {
                None
            },
            issuer_auth: CoseSign1::from_cbor_value(
                if let Some(issuer_auth) = fields.remove(&IssuerSigned::issuer_auth().into()) {
                    issuer_auth
                } else {
                    return Err(coset::CoseError::UnexpectedItem(
                        "value",
                        "Value for for CoseSign1",
                    ));
                },
            )?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut values = vec![];
        if let Some(namespaces) = self.namespaces {
            values.push((
                Value::Text(IssuerSigned::namespaces().to_string()),
                namespaces.to_cbor_value()?,
            ))
        }
        values.push((
            Value::Text(IssuerSigned::issuer_auth().to_string()),
            self.issuer_auth.to_cbor_value()?,
        ));
        Ok(Value::Map(values))
    }
}

#[cfg(test)]
mod test {
    use ciborium::Value;
    use coset::CborSerializable;
    use hex::FromHex;

    use crate::cose::sign1::CoseSign1;
    use crate::definitions::device_signed::{DeviceNamespaces, DeviceSignedItems};
    use crate::definitions::helpers::string_cbor::CborString;
    use crate::definitions::helpers::{ByteStr, NonEmptyMap, NonEmptyVec, Tag24};
    use crate::definitions::{DigestId, IssuerSignedItem};

    use super::{IssuerNamespaces, IssuerSigned, IssuerSignedItemBytes};

    static ISSUER_SIGNED_CBOR: &str = include_str!("../../test/definitions/issuer_signed.cbor");

    #[test]
    fn serde_issuer_signed_roundtrip() {
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

    #[test]
    fn ciborium_issuer_signed_roundtrip() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(ISSUER_SIGNED_CBOR).expect("unable to convert cbor hex to bytes");
        let signed: IssuerSigned = IssuerSigned::from_slice(&cbor_bytes)
            .expect("unable to decode cbor as an IssuerSigned");
        let roundtripped_bytes = signed
            .to_vec()
            .expect("unable to encode IssuerSigned as cbor bytes");
        assert_eq!(
            cbor_bytes, roundtripped_bytes,
            "original cbor and re-serialized IssuerSigned do not match"
        );
    }

    #[test]
    fn ciborium_issuer_signed_roundtrip2() {
        static COSE_SIGN1: &str = include_str!("../../test/definitions/cose/sign1/serialized.cbor");
        let cose_sign1 = CoseSign1::from_slice(&<Vec<u8>>::from_hex(COSE_SIGN1).unwrap()).unwrap();
        let device_signed_items =
            DeviceSignedItems::new(CborString::from("a"), Value::Text("b".to_string()));
        let mut device_namespaces = DeviceNamespaces::new();
        device_namespaces.insert(CborString::from("eu-dl".to_string()), device_signed_items);
        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId(0),
            random: ByteStr::from(vec![0, 1, 2, 3]),
            element_identifier: "a".to_string(),
            element_value: serde_cbor::Value::Text("b".to_string()),
        };
        let issuer_signed_item_bytes = IssuerSignedItemBytes::new(issuer_signed_item).unwrap();
        let issuer_signed_item_bytes_vec = NonEmptyVec::new(issuer_signed_item_bytes);
        let issuer_namespaces =
            IssuerNamespaces::new("a".to_string().into(), issuer_signed_item_bytes_vec);

        let issuer_signed = IssuerSigned {
            namespaces: Some(issuer_namespaces),
            issuer_auth: cose_sign1.clone(),
        };
        let bytes = issuer_signed.to_vec().unwrap();
        println!("{:?}", hex::encode(&bytes));
        let issuer_signed = IssuerSigned::from_slice(&bytes).unwrap();
        let bytes2 = issuer_signed.to_vec().unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn ciborium_issuer_signed_item_roundtrip() {
        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId(0),
            random: ByteStr::from(vec![0, 1, 2, 3]),
            element_identifier: "a".to_string(),
            element_value: serde_cbor::Value::Text("b".to_string()),
        };
        let bytes = issuer_signed_item.to_vec().unwrap();
        println!("{:?}", hex::encode(&bytes));
        let issuer_signed_item = IssuerSignedItem::from_slice(&bytes).unwrap();
        let bytes2 = issuer_signed_item.to_vec().unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn ciborium_issuer_signed_item_roundtrip2() {
        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId(0),
            random: ByteStr::from(vec![0, 1, 2, 3]),
            element_identifier: "a".to_string(),
            element_value: serde_cbor::Value::Text("b".to_string()),
        };
        let issuer_signed_item_bytes = IssuerSignedItemBytes::new(issuer_signed_item).unwrap();
        let bytes = issuer_signed_item_bytes.to_vec().unwrap();
        let issuer_signed_item_bytes = Tag24::<IssuerSignedItem>::from_slice(&bytes).unwrap();
        let bytes2 = issuer_signed_item_bytes.to_vec().unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn ciborium_issuer_signed_item_roundtrip3() {
        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId(0),
            random: ByteStr::from(vec![0, 1, 2, 3]),
            element_identifier: "a".to_string(),
            element_value: serde_cbor::Value::Text("b".to_string()),
        };
        let vec = NonEmptyMap::new(CborString::from("a"), issuer_signed_item);
        let bytes = vec.to_vec().unwrap();
        let vec = NonEmptyMap::<CborString, IssuerSignedItem>::from_slice(&bytes).unwrap();
        let bytes2 = vec.to_vec().unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn ciborium_issuer_signed_item_roundtrip4() {
        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId(0),
            random: ByteStr::from(vec![0, 1, 2, 3]),
            element_identifier: "a".to_string(),
            element_value: serde_cbor::Value::Text("b".to_string()),
        };
        let issuer_signed_item_bytes = IssuerSignedItemBytes::new(issuer_signed_item).unwrap();
        let issuer_signed_item_bytes_vec = NonEmptyVec::new(issuer_signed_item_bytes);
        let issuer_namespaces =
            IssuerNamespaces::new(CborString::from("a"), issuer_signed_item_bytes_vec);
        let bytes = issuer_namespaces.to_vec().unwrap();
        let issuer_namespaces =
            NonEmptyMap::<CborString, NonEmptyVec<IssuerSignedItemBytes>>::from_slice(&bytes)
                .unwrap();
        let bytes2 = issuer_namespaces.to_vec().unwrap();
        assert_eq!(bytes, bytes2);
    }
}
