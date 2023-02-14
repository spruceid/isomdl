use crate::definitions::{helpers::ByteStr, DeviceKeyInfo, ValidityInfo};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// TODO: When deserializing DigestId, check that it is not negative.

/// DigestId is a unsigned integer between 0 and (2^31 - 1) inclusive.
/// Therefore the most straightforward way to represent it is as a i32 that is enforced to be
/// positive.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd, Copy, Hash)]
pub struct DigestId(i32);
pub type DigestIds = BTreeMap<DigestId, ByteStr>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mso {
    pub version: String,
    pub digest_algorithm: DigestAlgorithm,
    pub value_digests: BTreeMap<String, DigestIds>,
    pub device_key_info: DeviceKeyInfo,
    pub doc_type: String,
    pub validity_info: ValidityInfo,
}

#[derive(Clone, Debug, Copy, Deserialize, Serialize)]
pub enum DigestAlgorithm {
    #[serde(rename = "SHA-256")]
    SHA256,
    #[serde(rename = "SHA-384")]
    SHA384,
    #[serde(rename = "SHA-512")]
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
    use hex::FromHex;

    static ISSUER_SIGNED_CBOR: &str = include_str!("../../test/definitions/issuer_signed.cbor");

    #[test]
    fn serde_mso() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(ISSUER_SIGNED_CBOR).expect("unable to convert cbor hex to bytes");
        let signed: IssuerSigned =
            serde_cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as an IssuerSigned");
        let mso_bytes = signed
            .issuer_auth
            .payload()
            .expect("expected a COSE_Sign1 with attached payload, found detached payload");
        let mso: Tag24<Mso> =
            serde_cbor::from_slice(mso_bytes).expect("unable to parse payload as Mso");
        let roundtripped_bytes =
            serde_cbor::to_vec(&mso).expect("unable to encode Mso as cbor bytes");
        assert_eq!(
            mso_bytes, &roundtripped_bytes,
            "original cbor and re-serialized Mso do not match"
        )
    }
}
