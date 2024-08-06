pub mod mac0;
mod serialize;
pub mod sign1;

use coset::iana;

/// Trait to represent the signature algorithm of a signer or verifier.
pub trait SignatureAlgorithm {
    fn algorithm(&self) -> iana::Algorithm;
}
