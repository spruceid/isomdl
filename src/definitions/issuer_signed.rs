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
use crate::definitions::{
    helpers::{ByteStr, NonEmptyMap, NonEmptyVec, Tag24},
    DigestId,
};
use cose_rs::sign1::CoseSign1;
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
