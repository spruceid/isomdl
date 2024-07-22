pub mod mac0;
pub mod sign1;

use coset::iana;

pub trait Cose {
    fn signature_payload(&self) -> &[u8];
    fn set_signature(&mut self, signature: Vec<u8>);
}

/// Trait to represent the signature algorithm of a signer or verifier.
pub trait SignatureAlgorithm {
    fn algorithm(&self) -> iana::Algorithm;
}
