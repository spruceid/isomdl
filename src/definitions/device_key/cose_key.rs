use std::collections::BTreeMap;

use crate::cbor::CborValue;
use aes::cipher::generic_array::{typenum::U8, GenericArray};
use ciborium::Value;
use coset::iana::{Algorithm, EllipticCurve};
use coset::{AsCborValue, CborSerializable};
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

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
    P256K,
}

impl CborSerializable for CoseKey {}
impl AsCborValue for CoseKey {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let v: CborValue = value.into();
        Ok(v.try_into().map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "invalid bytes".to_string(),
            ))
        })?)
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let v: CborValue = self.into();
        Ok(v.into())
    }
}

impl TryFrom<EllipticCurve> for EC2Curve {
    type Error = Error;

    fn try_from(value: EllipticCurve) -> Result<Self, Self::Error> {
        match value {
            EllipticCurve::Reserved => unimplemented!("{value:?} is not implemented"),
            EllipticCurve::P_256 => Ok(EC2Curve::P256),
            EllipticCurve::P_384 => Ok(EC2Curve::P384),
            EllipticCurve::P_521 => Ok(EC2Curve::P521),
            EllipticCurve::X25519 => Err(Error::UnsupportedCurve),
            EllipticCurve::X448 => Err(Error::UnsupportedCurve),
            EllipticCurve::Ed25519 => Err(Error::UnsupportedCurve),
            EllipticCurve::Ed448 => Err(Error::UnsupportedCurve),
            EllipticCurve::Secp256k1 => Err(Error::UnsupportedCurve),
            _ => Err(Error::UnsupportedCurve),
        }
    }
}

/// The RFC-8152 identifier of the curve, for OKP key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OKPCurve {
    X25519,
    X448,
    Ed25519,
    Ed448,
}

impl TryFrom<EllipticCurve> for OKPCurve {
    type Error = Error;

    fn try_from(value: EllipticCurve) -> Result<Self, Self::Error> {
        match value {
            EllipticCurve::X25519 => Ok(OKPCurve::X25519),
            EllipticCurve::X448 => Ok(OKPCurve::X448),
            EllipticCurve::Ed25519 => Ok(OKPCurve::Ed25519),
            EllipticCurve::Ed448 => Ok(OKPCurve::Ed448),
            _ => Err(Error::UnsupportedCurve),
        }
    }
}

/// Errors that can occur when deserialising a COSE_Key.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("COSE_Key of kty 'EC2' missing x coordinate")]
    EC2MissingX,
    #[error("COSE_Key of kty 'EC2' missing y coordinate")]
    EC2MissingY,
    #[error("Expected to parse a CBOR bool or bstr for y-coordinate, received: '{0:?}'")]
    InvalidTypeY(CborValue),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(CborValue),
    #[error("Unable to discern the elliptic curve")]
    UnknownCurve,
    #[error("This implementation of COSE_Key only supports P-256, P-384, P-521, Ed25519 and Ed448 elliptic curves")]
    UnsupportedCurve,
    #[error("This implementation of COSE_Key only supports EC2 and OKP keys")]
    UnsupportedKeyType,
    #[error("Could not reconstruct coordinates from the provided COSE_Key")]
    InvalidCoseKey,
    #[error("Constructing a JWK from CoseKey with point-compression is not supported.")]
    UnsupportedFormat,
}

impl CoseKey {
    pub fn signature_algorithm(&self) -> Option<Algorithm> {
        match self {
            CoseKey::EC2 {
                crv: EC2Curve::P256,
                ..
            } => Some(Algorithm::ES256),
            CoseKey::EC2 {
                crv: EC2Curve::P384,
                ..
            } => Some(Algorithm::ES384),
            CoseKey::EC2 {
                crv: EC2Curve::P521,
                ..
            } => Some(Algorithm::ES512),
            CoseKey::OKP {
                crv: OKPCurve::Ed448,
                ..
            } => Some(Algorithm::EdDSA),
            CoseKey::OKP {
                crv: OKPCurve::Ed25519,
                ..
            } => Some(Algorithm::EdDSA),
            _ => None,
        }
    }
}

impl From<CoseKey> for CborValue {
    fn from(key: CoseKey) -> CborValue {
        let mut map = BTreeMap::new();
        match key {
            CoseKey::EC2 { crv, x, y } => {
                // kty: 1, EC2: 2
                map.insert(CborValue::Integer(1), CborValue::Integer(2));
                // crv: -1
                map.insert(
                    CborValue::Integer(-1),
                    match crv {
                        EC2Curve::P256 => CborValue::Integer(1),
                        EC2Curve::P384 => CborValue::Integer(2),
                        EC2Curve::P521 => CborValue::Integer(3),
                        EC2Curve::P256K => CborValue::Integer(8),
                    },
                );
                // x: -2
                map.insert(CborValue::Integer(-2), CborValue::Bytes(x));
                // y: -3
                map.insert(
                    CborValue::Integer(-3),
                    match y {
                        EC2Y::Value(v) => CborValue::Bytes(v),
                        EC2Y::SignBit(b) => CborValue::Bool(b),
                    },
                );
            }
            CoseKey::OKP { crv, x } => {
                // kty: 1, OKP: 1
                map.insert(CborValue::Integer(1), CborValue::Integer(1));
                // crv: -1
                map.insert(
                    CborValue::Integer(-1),
                    match crv {
                        OKPCurve::X25519 => CborValue::Integer(4),
                        OKPCurve::X448 => CborValue::Integer(5),
                        OKPCurve::Ed25519 => CborValue::Integer(6),
                        OKPCurve::Ed448 => CborValue::Integer(7),
                    },
                );
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
                    Some(CborValue::Integer(i2)),
                    Some(CborValue::Integer(crv_id)),
                    Some(CborValue::Bytes(x)),
                ) if i2 == 2 => {
                    let crv: i128 = crv_id;
                    let crv = match crv {
                        1 => EC2Curve::P256,
                        2 => EC2Curve::P384,
                        3 => EC2Curve::P521,
                        8 => EC2Curve::P256K,
                        _ => return Err(Error::InvalidCoseKey),
                    };
                    let y: CborValue = map
                        .remove(&CborValue::Integer(-3))
                        .ok_or(Error::EC2MissingY)?;
                    let y = match y {
                        CborValue::Bytes(v) => EC2Y::Value(v),
                        CborValue::Bool(b) => EC2Y::SignBit(b),
                        _ => return Err(Error::InvalidCoseKey),
                    };
                    Ok(Self::EC2 { crv, x, y })
                }
                (
                    Some(CborValue::Integer(i1)),
                    Some(CborValue::Integer(crv_id)),
                    Some(CborValue::Bytes(x)),
                ) if i1 == 1 => {
                    let crv = match crv_id {
                        4 => OKPCurve::X25519,
                        5 => OKPCurve::X448,
                        6 => OKPCurve::Ed25519,
                        7 => OKPCurve::Ed448,
                        _ => return Err(Error::InvalidCoseKey),
                    };
                    Ok(Self::OKP { crv, x })
                }
                _ => Err(Error::UnsupportedKeyType),
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
            CoseKey::EC2 {
                crv: EC2Curve::P256,
                x,
                y,
            } => {
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
                        let mut bytes = x;
                        if y {
                            bytes.insert(0, 3)
                        } else {
                            bytes.insert(0, 2)
                        }

                        let encoded =
                            EncodedPoint::from_bytes(bytes).map_err(|_e| Error::InvalidCoseKey)?;
                        Ok(encoded)
                    }
                }
            }
            CoseKey::OKP { crv: _, x } => {
                let x_generic_array: GenericArray<_, U8> =
                    GenericArray::clone_from_slice(&x[0..42]);
                let encoded = EncodedPoint::from_bytes(x_generic_array)
                    .map_err(|_e| Error::InvalidCoseKey)?;
                Ok(encoded)
            }
            _ => Err(Error::InvalidCoseKey),
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
            EC2Curve::P256K => CborValue::Integer(8),
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
            8 => Ok(EC2Curve::P256K),
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

impl TryFrom<JWK> for CoseKey {
    type Error = Error;

    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        match jwk.params {
            ssi_jwk::Params::EC(params) => {
                let x = params
                    .x_coordinate
                    .as_ref()
                    .ok_or(Error::EC2MissingX)?
                    .0
                    .clone();
                Ok(CoseKey::EC2 {
                    crv: (&params).try_into()?,
                    x,
                    y: params.try_into()?,
                })
            }
            ssi_jwk::Params::OKP(params) => Ok(CoseKey::OKP {
                crv: (&params).try_into()?,
                x: params.public_key.0.clone(),
            }),
            _ => Err(Error::UnsupportedKeyType),
        }
    }
}

impl TryFrom<&ssi_jwk::ECParams> for EC2Curve {
    type Error = Error;

    fn try_from(params: &ssi_jwk::ECParams) -> Result<Self, Self::Error> {
        match params.curve.as_ref() {
            Some(crv) if crv == "P-256" => Ok(Self::P256),
            Some(crv) if crv == "P-384" => Ok(Self::P384),
            Some(crv) if crv == "P-521" => Ok(Self::P521),
            Some(crv) if crv == "secp256k1" => Ok(Self::P256K),
            Some(_) => Err(Error::UnsupportedCurve),
            None => Err(Error::UnknownCurve),
        }
    }
}

impl TryFrom<ssi_jwk::ECParams> for EC2Y {
    type Error = Error;

    fn try_from(params: ssi_jwk::ECParams) -> Result<Self, Self::Error> {
        if let Some(y) = params.y_coordinate.as_ref() {
            Ok(Self::Value(y.0.clone()))
        } else {
            Err(Error::EC2MissingY)
        }
    }
}

impl TryFrom<CoseKey> for JWK {
    type Error = Error;
    fn try_from(cose: CoseKey) -> Result<JWK, Error> {
        Ok(match cose {
            CoseKey::EC2 { crv, x, y } => JWK {
                params: ssi_jwk::Params::EC(ssi_jwk::ECParams {
                    curve: Some(match crv {
                        EC2Curve::P256 => "P-256".to_string(),
                        EC2Curve::P384 => "P-384".to_string(),
                        EC2Curve::P521 => "P-521".to_string(),
                        EC2Curve::P256K => "secp256k1".to_string(),
                    }),
                    x_coordinate: Some(ssi_jwk::Base64urlUInt(x)),
                    y_coordinate: match y {
                        EC2Y::Value(vec) => Some(ssi_jwk::Base64urlUInt(vec)),
                        EC2Y::SignBit(_) => return Err(Error::UnsupportedFormat),
                    },
                    ecc_private_key: None,
                }),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            },
            CoseKey::OKP { crv, x } => JWK {
                params: ssi_jwk::Params::OKP(ssi_jwk::OctetParams {
                    curve: match crv {
                        OKPCurve::X25519 => "X25519".to_string(),
                        OKPCurve::X448 => "X448".to_string(),
                        OKPCurve::Ed25519 => "Ed25519".to_string(),
                        OKPCurve::Ed448 => "Ed448".to_string(),
                    },
                    public_key: ssi_jwk::Base64urlUInt(x),
                    private_key: None,
                }),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            },
        })
    }
}

impl TryFrom<&ssi_jwk::OctetParams> for OKPCurve {
    type Error = Error;

    fn try_from(params: &ssi_jwk::OctetParams) -> Result<Self, Self::Error> {
        match params.curve.as_str() {
            "Ed25519" => Ok(Self::Ed25519),
            "Ed448" => Ok(Self::Ed448),
            "X25519" => Ok(Self::X25519),
            "X448" => Ok(Self::X448),
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

    #[test]
    fn cose_key() {
        let key = CoseKey::EC2 {
            crv: EC2Curve::P256,
            x: vec![0x01, 0x02, 0x03],
            y: EC2Y::Value(vec![0x04, 0x05, 0x06]),
        };
        let cbor = key.clone().to_vec().unwrap();
        println!("{:?}", hex::encode(&cbor));
        let key2: CoseKey = serde_cbor::from_slice(&cbor).unwrap();
        assert_eq!(key, key2);
    }
}
