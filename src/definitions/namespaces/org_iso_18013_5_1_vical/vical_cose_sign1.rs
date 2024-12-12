use crate::definitions::namespaces::org_iso_18013_5_1_vical::OrgIso1901351Vical;
use coset::{iana, CoseSign1};
use p256::ecdsa::{Signature};
use signature::{SignatureEncoding, Signer};
use crate::cose::SignatureAlgorithm;
use crate::definitions::traits::ToCbor;

pub fn sign_vical<S, Sig>(vical: OrgIso1901351Vical, signer: &S) -> CoseSign1
where
    S: Signer<Sig> + SignatureAlgorithm,
    Sig: SignatureEncoding
{
    let aad = b"";
    let protected = coset::HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();

    let cose_sign = coset::CoseSign1Builder::new()
        .protected(protected)
        .payload(vical.to_cbor_bytes().unwrap())
        .create_signature(aad, |pt| signer.sign(pt).to_vec()) // closure to do sign operation
        .build();
    cose_sign
}
#[cfg(test)]
mod tests {
    use coset::CborSerializable;
    use hex::FromHex;
    use p256::ecdsa::{SigningKey};
    use p256::SecretKey;
    use crate::definitions::traits::FromJson;
    use super::*;
    static COSE_KEY: &str = include_str!("../../../../test/definitions/cose/sign1/secret_key");
    #[test]
    fn test_sign_vical() {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();

        let json = serde_json::json!({
            "version": "1.0.0",
            "vical_provider": "Spruce",
            "date": "2024-12-31T12:00:00Z",
            "vical_issue_id": 1,
            "next_update": "2022-03-21T13:30:00Z",
            "certificate_infos": [
                {
                    "certificate": "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
                    "serial_number": "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
                    "ski": "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
                    "doc_type": ["somedoc"],
                    "certificate_profile": ["profile"],
                    "extensions": {"extension_name": "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"},
                }
            ]
        });
        let vical = OrgIso1901351Vical::from_json(&json).unwrap();
        let sign = sign_vical::<SigningKey, Signature>(vical, &signer);

        let sign_data = sign.to_vec().unwrap();
        let sign1 = coset::CoseSign1::from_slice(&sign_data).unwrap();
        // let result = sign1.verify_signature(b"", |sig, data| verifier.verify(sig, data));
        // println!("Signature verified: {:?}.", result);
        // assert!(result.is_ok());
        // println!("{:#?}", hex::encode(&sign.to_vec().unwrap()));
    }
}