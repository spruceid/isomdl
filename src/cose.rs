pub mod mac0;
mod serialize;
pub mod sign1;

use std::any::type_name;

use coset::iana;

/// Trait to represent the signature algorithm of a signer or verifier.
pub trait SignatureAlgorithm {
    fn algorithm(&self) -> iana::Algorithm;
}

pub fn into_cbor_value<T>(val: T) -> coset::Result<ciborium::Value> {
    match type_name::<T>() {
        "str" => Ok(ciborium::Value::Text(val.into())),
        _ => Err(coset::CoseError::EncodeFailed),
    }
}
