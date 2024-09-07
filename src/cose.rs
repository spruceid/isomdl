use coset::iana;
pub mod mac0;
mod serialized_as_cbor_value;
pub mod sign1;

/// Trait to represent the signature algorithm of a signer or verifier.
pub trait SignatureAlgorithm {
    fn algorithm(&self) -> iana::Algorithm;
}
