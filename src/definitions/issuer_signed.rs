use crate::definitions::{
    helpers::{ByteStr, NonEmptyMap, NonEmptyVec, Tag24},
    DigestId,
};
use cose_rs::sign1::CoseSign1;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    #[serde(skip_serializing_if = "Option::is_none", rename = "nameSpaces")]
    pub namespaces: Option<IssuerNamespaces>,
    pub issuer_auth: CoseSign1,
}

pub type IssuerNamespaces = NonEmptyMap<String, NonEmptyVec<IssuerSignedItemBytes>>;
pub type IssuerSignedItemBytes = Tag24<IssuerSignedItem>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    #[serde(rename = "digestID")]
    pub digest_id: DigestId,
    pub random: ByteStr,
    pub element_identifier: String,
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

    use super::super::{helpers::Tag24, Mso};
    use super::*;
    use crate::issuance::Mdoc;
    use crate::presentation::{device::Document, Stringify};

    #[test]
    fn debug() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(ISSUER_SIGNED_CBOR).expect("unable to convert cbor hex to bytes");
        let signed: IssuerSigned =
            serde_cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as an IssuerSigned");

        let portrait_bytes = signed
            .namespaces
            .unwrap()
            .get("org.iso.18013.5.1")
            .unwrap()
            .clone()
            .into_inner()
            .into_iter()
            .map(|t| t.into_inner())
            .find(|item| item.element_identifier == "portrait")
            .and_then(|item| match item.element_value {
                CborValue::Bytes(b) => Some(b),
                _ => None,
            })
            .unwrap();

        use std::io::Write;
        let file = std::fs::File::create("ex-portrait.jpg")
            .unwrap()
            .write_all(&portrait_bytes)
            .unwrap();

        // Issue mDL
        //
        //let t_mso: Tag24<Mso> = serde_cbor::from_slice(&signed.issuer_auth.payload().unwrap()).unwrap();
        //let mso = t_mso.into_inner();
        //let doc_type = String::from("org.iso.18013.5.1.mDL");
        //let doc: Document = Mdoc {
        //    doc_type,
        //    mso,
        //    namespaces: signed.namespaces.unwrap(),
        //    issuer_auth: signed.issuer_auth,
        //}.into();
        //println!("example mdoc: {}", doc.stringify().unwrap())
    }
}
