use ciborium::Value;
use serde::{Deserialize, Serialize};

use crate::definitions::{
    device_request::DocType,
    helpers::{ByteStr, NonEmptyVec},
    namespaces::org_iso_18013_5_1::TDate,
};

pub type Extensions = Vec<(Value, Value)>;
pub type CertificateProfile = String;

/// VICAL profile as defined in C.1.7.1
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    // try_from = "ciborium::Value",
    // into = "ciborium::Value",
    rename_all = "camelCase"
)]
pub struct Vical {
    /// The version of the device engagement.
    pub version: String,
    /// Identifies the VICAL provider
    pub vical_provider: String,
    /// date-time of VICAL issuance
    pub date: TDate,
    /// identifies the specific issue of the VICAL, shall be unique and monotonically increasing
    #[serde(rename = "vicalIssueID", skip_serializing_if = "Option::is_none")]
    pub vical_issue_id: Option<u64>,
    /// next VICAL is expected to be issued before this date-time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<TDate>,
    pub certificate_infos: Vec<CertificateInfo>,
    /// Can be used for proprietary extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    /// URL where this VICAL can be retrieved
    #[serde(rename = "vicalURL", skip_serializing_if = "Option::is_none")]
    pub vical_url: Option<String>,
}

/// CertificateInfo profile as defined in C.1.7.1
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    // try_from = "ciborium::Value",
    // into = "ciborium::Value",
    rename_all = "camelCase"
)]
pub struct CertificateInfo {
    /// DER-encoded X.509 certificate
    pub certificate: ByteStr,
    /// value of the serial number field of the certificate
    pub serial_number: Vec<u8>, // this is supposed to be a biguint but even u128 is too small
    /// value of the Subject Key Identifier field of the certificate
    pub ski: ByteStr,
    /// DocType for which the certificate may be used as a trust point
    pub doc_type: NonEmptyVec<DocType>,
    /// Type of certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_profile: Option<NonEmptyVec<CertificateProfile>>,
    /// Name of the certificate issuing authority
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_authority: Option<String>,
    /// ISO3166-1 or ISO3166-2 depending on the issuing authority
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_country: Option<String>,
    /// State or province name of the certificate issuing authority
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_or_province_name: Option<String>,
    /// DER-encoded Issuer field of the certificate (i.e. the complete Name structure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<ByteStr>,
    /// DER-encoded Subject field of the certificate (i.e. the complete Name structure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<ByteStr>,
    /// value of the notBefore field of the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<TDate>,
    /// value of the notAfter field of the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<TDate>,
    /// Can be used for proprietary extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
}

#[cfg(test)]
mod test {
    use coset::{iana, CoseSign1, Label};

    use crate::{
        cbor,
        cose::{sign1::VerificationResult, MaybeTagged},
        definitions::x509::X5Chain,
    };

    use super::*;

    // https://vical.dts.aamva.org/
    static AAMVA_VICAL: &[u8] = include_bytes!("../../test/vical/vc-2025-11-18-1763491092481.cbor");
    // TODO verify cert with chain from https://vical.dts.aamva.org/trustcertificates

    #[test]
    fn process_aamva_vical() {
        let cose_sign1: MaybeTagged<CoseSign1> =
            cbor::from_slice(AAMVA_VICAL).expect("failed to parse COSE_Sign1 from bytes");
        let x5chain = cose_sign1
            .unprotected
            .rest
            .iter()
            .find(|x| x.0 == Label::Int(iana::HeaderParameter::X5Chain as i64))
            .expect("no x509 chain in the cose sign1")
            .1
            .clone();
        let x5chain = X5Chain::from_cbor(x5chain).expect("failed to parse x5chain");
        let verifier: p256::ecdsa::VerifyingKey = x5chain
            .end_entity_public_key()
            .expect("failed to get leaf cert public key");
        let res = cose_sign1.verify::<_, p256::ecdsa::Signature>(&verifier, None, None);
        match res {
            VerificationResult::Success => (),
            e => panic!("verification failed: {e:?}"),
        }
        let payload = cose_sign1.payload.as_ref().expect("no payload present");
        let vical: Vical = cbor::from_slice(payload).expect("unable to devoce cbor as a Vical");
        for cert_info in vical.certificate_infos {
            println!("{:?}", cert_info.issuing_authority);
        }
        println!("{:?}", vical.vical_provider);
        println!("{:?}", x5chain.end_entity_common_name());
        println!("{:?}", x5chain.root_entity_common_name());
    }
}
