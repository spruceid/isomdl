pub mod mac0;
mod serialize;
pub mod sign1;

use coset::iana;
use serde_cbor::Value as CborValue;

/// Trait to represent the signature algorithm of a signer or verifier.
pub trait SignatureAlgorithm {
    fn algorithm(&self) -> iana::Algorithm;
}

pub fn serde_cbor_value_into_ciborium_value(val: CborValue) -> coset::Result<ciborium::Value> {
    match val {
        CborValue::Null => Ok(ciborium::Value::Null),
        CborValue::Bool(b) => Ok(ciborium::Value::Bool(b)),
        CborValue::Integer(i) => Ok(ciborium::Value::Integer(i.try_into()?)),
        CborValue::Float(f) => Ok(ciborium::Value::Float(f)),
        CborValue::Bytes(b) => Ok(ciborium::Value::Bytes(b)),
        CborValue::Text(t) => Ok(ciborium::Value::Text(t)),
        CborValue::Array(a) => Ok(ciborium::Value::Array(
            a.into_iter()
                .flat_map(serde_cbor_value_into_ciborium_value)
                .collect(),
        )),
        CborValue::Map(m) => Ok(ciborium::Value::Map(
            m.into_iter()
                .flat_map(|(k, v)| {
                    Ok::<(ciborium::Value, ciborium::Value), coset::CoseError>((
                        serde_cbor_value_into_ciborium_value(k)?,
                        serde_cbor_value_into_ciborium_value(v)?,
                    ))
                })
                .collect(),
        )),
        CborValue::Tag(t, v) => Ok(ciborium::Value::Tag(
            t,
            Box::new(serde_cbor_value_into_ciborium_value(*v)?),
        )),
        _ => unimplemented!("Unsupported cbor value {val:?}"),
    }
}

pub fn ciborium_value_into_serde_cbor_value(val: ciborium::Value) -> coset::Result<CborValue> {
    match val {
        ciborium::Value::Null => Ok(CborValue::Null),
        ciborium::Value::Bool(b) => Ok(CborValue::Bool(b)),
        ciborium::Value::Integer(i) => Ok(CborValue::Integer(i.into())),
        ciborium::Value::Float(f) => Ok(CborValue::Float(f)),
        ciborium::Value::Bytes(b) => Ok(CborValue::Bytes(b)),
        ciborium::Value::Text(t) => Ok(CborValue::Text(t)),
        ciborium::Value::Array(a) => Ok(CborValue::Array(
            a.into_iter()
                .flat_map(ciborium_value_into_serde_cbor_value)
                .collect(),
        )),
        ciborium::Value::Map(m) => Ok(CborValue::Map(
            m.into_iter()
                .flat_map(|(k, v)| {
                    Ok::<(CborValue, CborValue), coset::CoseError>((
                        ciborium_value_into_serde_cbor_value(k)?,
                        ciborium_value_into_serde_cbor_value(v)?,
                    ))
                })
                .collect(),
        )),
        ciborium::Value::Tag(t, v) => Ok(CborValue::Tag(
            t,
            Box::new(ciborium_value_into_serde_cbor_value(*v)?),
        )),
        _ => unimplemented!("Unsupported cbor value {val:?}"),
    }
}
