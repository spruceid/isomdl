use crate::definitions::namespaces::org_iso_18013_5_1_vical::OrgIso1901351Vical;
use coset::{CborSerializable, CoseSign1};
use p256::ecdsa::{Signature};
use signature::{Signer, Verifier};
use crate::cose::{SignatureAlgorithm};
use crate::definitions::traits::ToCbor;

pub fn sign_vical<S>(vical: OrgIso1901351Vical, signer: &S) -> CoseSign1
where
    S: Signer<Signature> + SignatureAlgorithm,
{
    let aad = b"";
    let protected = coset::HeaderBuilder::new()
        .algorithm(signer.algorithm())
        .key_id(b"11".to_vec())
        .build();

    coset::CoseSign1Builder::new()
        .protected(protected)
        .payload(vical.to_cbor_bytes().unwrap())
        .create_signature(aad, |pt| signer.sign(pt).to_vec())
        .build()
}
pub fn verify_vical<V>(sign_data: Vec<u8>, verifier: &V) -> Result<(), signature::Error>
where
    V: Verifier<Signature> + SignatureAlgorithm,
{
    let aad = b"";
    let cose_sign1 = CoseSign1::from_slice(&sign_data).unwrap();
    cose_sign1.verify_signature(aad, |sig, data| verifier.verify(data, &Signature::from_slice(sig).unwrap()))
}
#[cfg(test)]
mod tests {
    use coset::CborSerializable;
    use hex::FromHex;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::SecretKey;
    use crate::definitions::traits::FromJson;
    use super::*;
    static COSE_KEY: &str = include_str!("../../../../test/definitions/cose/sign1/secret_key");
    static JSON_VICAL: &str = include_str!("../../../../test/definitions/namespaces/org_iso_18013_5_1_vical/vical.json");
    #[test]
    fn test_sign_vical() {
        let key_bytes = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key_bytes).unwrap().into();
        let verifier = VerifyingKey::from(&signer);
        let json_vical: serde_json::Value = serde_json::from_str(JSON_VICAL).unwrap();
        let vical = OrgIso1901351Vical::from_json(&json_vical).unwrap();
        let sign = sign_vical::<SigningKey>(vical, &signer);
        // println!("{:#?}", hex::encode(sign.to_vec().unwrap()));
        let sign_data = sign.to_vec().unwrap();
        let result = verify_vical::<VerifyingKey>(sign_data, &verifier);
        println!("Signature verified: {:?}.", result);
        assert!(result.is_ok());
    }
}