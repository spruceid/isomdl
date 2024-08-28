use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};

use coset::{iana, CborSerializable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod mac0;
mod serialize;
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
