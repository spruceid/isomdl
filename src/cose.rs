use coset::iana;

pub mod mac0;
pub mod sign1;

/// Tag constants
pub mod tag {
    #![allow(missing_docs)]

    pub const BIGPOS: u64 = 2;
    pub const BIGNEG: u64 = 3;
}

/// Trait to represent the signature algorithm of a signer or verifier.
pub trait SignatureAlgorithm {
    fn algorithm(&self) -> iana::Algorithm;
}
