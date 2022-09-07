use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;

/// An implementation of RFC-8152 [COSE_Key](https://datatracker.ietf.org/doc/html/rfc8152#section-13)
/// restricted to the requirements of ISO/IEC 18013-5:2021.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "Value", into = "Value")]
pub enum CoseKey {
    EC2 { crv: EC2Curve, x: Vec<u8>, y: EC2_Y },
    OKP { crv: OKPCurve, x: Vec<u8> },
}

/// The sign bit or value of the y-coordinate for the EC point.
#[derive(Debug, Clone)]
pub enum EC2_Y {
    Value(Vec<u8>),
    SignBit(bool),
}

/// The RFC-8152 identifier of the curve, for EC2 key type.
#[derive(Debug, Clone)]
pub enum EC2Curve {
    P256,
    P384,
    P521,
    // TODO: Support for brainpool curves can be added when they are added to the IANA COSE
    // Elliptic Curves registry.
}

/// The RFC-8152 identifier of the curve, for OKP key type.
#[derive(Debug, Clone)]
pub enum OKPCurve {
    X25519,
    X448,
    Ed25519,
    Ed448,
}

/// Errors that can occur when deserialising a COSE_Key.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("COSE_Key of kty 'EC2' missing y coordinate.")]
    EC2MissingY,
    #[error("Expected to parse a CBOR bool or bstr for y-coordinate, received: '{0:?}'")]
    InvalidTypeY(Value),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(Value),
    #[error("This implementation of COSE_Key only supports P-256, P-384, P-521, Ed25519 and Ed448 elliptic curves.")]
    UnsupportedCurve,
    #[error("This implementation of COSE_Key only supports EC2 and OKP keys.")]
    UnsupportedFormat,
}

impl From<CoseKey> for Value {
    fn from(key: CoseKey) -> Value {
        let mut map = BTreeMap::new();
        match key {
            CoseKey::EC2 { crv, x, y } => {
                // kty: 1, EC2: 2
                map.insert(Value::Integer(1), Value::Integer(2));
                // crv: -1
                map.insert(Value::Integer(-1), crv.into());
                // x: -2
                map.insert(Value::Integer(-2), Value::Bytes(x));
                // y: -3
                map.insert(Value::Integer(-3), y.into());
            }
            CoseKey::OKP { crv, x } => {
                // kty: 1, OKP: 1
                map.insert(Value::Integer(1), Value::Integer(1));
                // crv: -1
                map.insert(Value::Integer(-1), crv.into());
                // x: -2
                map.insert(Value::Integer(-2), Value::Bytes(x));
            }
        }
        Value::Map(map)
    }
}

impl TryFrom<Value> for CoseKey {
    type Error = Error;

    fn try_from(v: Value) -> Result<Self, Error> {
        if let Value::Map(mut map) = v {
            match (
                map.remove(&Value::Integer(1)),
                map.remove(&Value::Integer(-1)),
                map.remove(&Value::Integer(-2)),
            ) {
                (Some(Value::Integer(2)), Some(Value::Integer(crv_id)), Some(Value::Bytes(x))) => {
                    let crv = crv_id.try_into()?;
                    let y = map
                        .remove(&Value::Integer(-3))
                        .ok_or(Error::EC2MissingY)?
                        .try_into()?;
                    Ok(Self::EC2 { crv, x, y })
                }
                (Some(Value::Integer(1)), Some(Value::Integer(crv_id)), Some(Value::Bytes(x))) => {
                    let crv = crv_id.try_into()?;
                    Ok(Self::OKP { crv, x })
                }
                _ => Err(Error::UnsupportedFormat),
            }
        } else {
            Err(Error::NotAMap(v))
        }
    }
}

impl From<EC2_Y> for Value {
    fn from(y: EC2_Y) -> Value {
        match y {
            EC2_Y::Value(s) => Value::Bytes(s),
            EC2_Y::SignBit(b) => Value::Bool(b),
        }
    }
}

impl TryFrom<Value> for EC2_Y {
    type Error = Error;

    fn try_from(v: Value) -> Result<Self, Error> {
        match v {
            Value::Bytes(s) => Ok(EC2_Y::Value(s)),
            Value::Bool(b) => Ok(EC2_Y::SignBit(b)),
            _ => Err(Error::InvalidTypeY(v)),
        }
    }
}

impl From<EC2Curve> for Value {
    fn from(crv: EC2Curve) -> Value {
        match crv {
            EC2Curve::P256 => Value::Integer(1),
            EC2Curve::P384 => Value::Integer(2),
            EC2Curve::P521 => Value::Integer(3),
        }
    }
}

impl TryFrom<i128> for EC2Curve {
    type Error = Error;

    fn try_from(crv_id: i128) -> Result<Self, Error> {
        match crv_id {
            1 => Ok(EC2Curve::P256),
            2 => Ok(EC2Curve::P384),
            3 => Ok(EC2Curve::P521),
            _ => Err(Error::UnsupportedCurve),
        }
    }
}

impl From<OKPCurve> for Value {
    fn from(crv: OKPCurve) -> Value {
        match crv {
            OKPCurve::X25519 => Value::Integer(4),
            OKPCurve::X448 => Value::Integer(5),
            OKPCurve::Ed25519 => Value::Integer(6),
            OKPCurve::Ed448 => Value::Integer(7),
        }
    }
}

impl TryFrom<i128> for OKPCurve {
    type Error = Error;

    fn try_from(crv_id: i128) -> Result<Self, Error> {
        match crv_id {
            4 => Ok(OKPCurve::X25519),
            5 => Ok(OKPCurve::X448),
            6 => Ok(OKPCurve::Ed25519),
            7 => Ok(OKPCurve::Ed448),
            _ => Err(Error::UnsupportedCurve),
        }
    }
}
