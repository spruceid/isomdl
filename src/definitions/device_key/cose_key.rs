use aes::cipher::generic_array::{typenum::U8, GenericArray};
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::collections::BTreeMap;

/// An implementation of RFC-8152 [COSE_Key](https://datatracker.ietf.org/doc/html/rfc8152#section-13)
/// restricted to the requirements of ISO/IEC 18013-5:2021.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub enum CoseKey {
    EC2 { crv: EC2Curve, x: Vec<u8>, y: EC2Y },
    OKP { crv: OKPCurve, x: Vec<u8> },
}

/// The sign bit or value of the y-coordinate for the EC point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EC2Y {
    Value(Vec<u8>),
    SignBit(bool),
}

/// The RFC-8152 identifier of the curve, for EC2 key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EC2Curve {
    P256,
    P384,
    P521,
    // TODO: Support for brainpool curves can be added when they are added to the IANA COSE
    // Elliptic Curves registry.
}

/// The RFC-8152 identifier of the curve, for OKP key type.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    InvalidTypeY(CborValue),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(CborValue),
    #[error("This implementation of COSE_Key only supports P-256, P-384, P-521, Ed25519 and Ed448 elliptic curves.")]
    UnsupportedCurve,
    #[error("This implementation of COSE_Key only supports EC2 and OKP keys.")]
    UnsupportedFormat,
}

impl From<CoseKey> for CborValue {
    fn from(key: CoseKey) -> CborValue {
        let mut map = BTreeMap::new();
        match key {
            CoseKey::EC2 { crv, x, y } => {
                // kty: 1, EC2: 2
                map.insert(CborValue::Integer(1), CborValue::Integer(2));
                // crv: -1
                map.insert(CborValue::Integer(-1), crv.into());
                // x: -2
                map.insert(CborValue::Integer(-2), CborValue::Bytes(x));
                // y: -3
                map.insert(CborValue::Integer(-3), y.into());
            }
            CoseKey::OKP { crv, x } => {
                // kty: 1, OKP: 1
                map.insert(CborValue::Integer(1), CborValue::Integer(1));
                // crv: -1
                map.insert(CborValue::Integer(-1), crv.into());
                // x: -2
                map.insert(CborValue::Integer(-2), CborValue::Bytes(x));
            }
        }
        CborValue::Map(map)
    }
}

impl TryFrom<CborValue> for CoseKey {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<Self, Error> {
        if let CborValue::Map(mut map) = v {
            match (
                map.remove(&CborValue::Integer(1)),
                map.remove(&CborValue::Integer(-1)),
                map.remove(&CborValue::Integer(-2)),
            ) {
                (
                    Some(CborValue::Integer(2)),
                    Some(CborValue::Integer(crv_id)),
                    Some(CborValue::Bytes(x)),
                ) => {
                    let crv = crv_id.try_into()?;
                    let y = map
                        .remove(&CborValue::Integer(-3))
                        .ok_or(Error::EC2MissingY)?
                        .try_into()?;
                    Ok(Self::EC2 { crv, x, y })
                }
                (
                    Some(CborValue::Integer(1)),
                    Some(CborValue::Integer(crv_id)),
                    Some(CborValue::Bytes(x)),
                ) => {
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

impl TryFrom<CoseKey> for EncodedPoint {
    type Error = Error;
    fn try_from(value: CoseKey) -> Result<EncodedPoint, Self::Error> {
        match value {
            CoseKey::EC2 { crv, x, y } => {
                let x_generic_array = GenericArray::from_slice(x.as_ref());
                match y {
                    EC2Y::Value(y) => {
                        let y_generic_array = GenericArray::from_slice(y.as_ref());

                        Ok(EncodedPoint::from_affine_coordinates(
                            x_generic_array,
                            y_generic_array,
                            false,
                        ))
                    }
                    EC2Y::SignBit(y) => {
                        //TODO: get rid of unwrap
                        let encoded = EncodedPoint::from_bytes(x_generic_array).unwrap();
                        Ok(encoded)
                    }
                }
            }
            CoseKey::OKP { crv, x } => {
                //TODO: get rid of unwrap
                let x_generic_array: GenericArray<_, U8> =
                    GenericArray::clone_from_slice(&x[0..42]);
                let encoded = EncodedPoint::from_bytes(x_generic_array).unwrap();
                Ok(encoded)
            }
        }
    }
}

impl From<EC2Y> for CborValue {
    fn from(y: EC2Y) -> CborValue {
        match y {
            EC2Y::Value(s) => CborValue::Bytes(s),
            EC2Y::SignBit(b) => CborValue::Bool(b),
        }
    }
}

impl TryFrom<CborValue> for EC2Y {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<Self, Error> {
        match v {
            CborValue::Bytes(s) => Ok(EC2Y::Value(s)),
            CborValue::Bool(b) => Ok(EC2Y::SignBit(b)),
            _ => Err(Error::InvalidTypeY(v)),
        }
    }
}

impl From<EC2Curve> for CborValue {
    fn from(crv: EC2Curve) -> CborValue {
        match crv {
            EC2Curve::P256 => CborValue::Integer(1),
            EC2Curve::P384 => CborValue::Integer(2),
            EC2Curve::P521 => CborValue::Integer(3),
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

impl From<OKPCurve> for CborValue {
    fn from(crv: OKPCurve) -> CborValue {
        match crv {
            OKPCurve::X25519 => CborValue::Integer(4),
            OKPCurve::X448 => CborValue::Integer(5),
            OKPCurve::Ed25519 => CborValue::Integer(6),
            OKPCurve::Ed448 => CborValue::Integer(7),
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

#[cfg(test)]
mod test {
    use super::*;
    use hex::FromHex;

    static EC_P256: &str = include_str!("../../../test/definitions/cose_key/ec_p256.cbor");

    #[test]
    fn ec_p256() {
        let key_bytes = <Vec<u8>>::from_hex(EC_P256).expect("unable to convert cbor hex to bytes");
        let key = serde_cbor::from_slice(&key_bytes).unwrap();
        match &key {
            CoseKey::EC2 { crv, .. } => assert_eq!(crv, &EC2Curve::P256),
            _ => panic!("expected an EC2 cose key"),
        };
        assert_eq!(
            serde_cbor::to_vec(&key).unwrap(),
            key_bytes,
            "cbor encoding roundtrip failed"
        );
    }
}
