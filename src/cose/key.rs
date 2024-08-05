use aes::cipher::consts::U8;
use aes::cipher::generic_array::GenericArray;
use ciborium::Value;
use coset::iana::{Algorithm, EllipticCurve, EnumI64};
use coset::{iana, AsCborValue, KeyType, Label};
use p256::EncodedPoint;
use serde::ser;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::Deserialize;
use serde::Deserializer;
use serde_cbor::tags::Tagged;
use serde_cbor::Value as CborValue;
use ssi_jwk::JWK;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub struct CoseKey(coset::CoseKey);

/// Errors that can occur when deserializing a COSE_Key.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("COSE_Key of kty 'EC2' missing x coordinate")]
    EC2MissingX,
    #[error("COSE_Key of kty 'EC2' missing y coordinate")]
    EC2MissingY,
    #[error("Expected to parse a CBOR bool or bstr for y-coordinate, received: '{0:?}'")]
    InvalidTypeY(serde_cbor::Value),
    #[error("Expected to parse a CBOR bool for y-coordinate, received: '{0:?}'")]
    InvalidTypeYSign(Value),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(serde_cbor::Value),
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

impl Eq for CoseKey {}

impl CoseKey {
    pub fn new(key: coset::CoseKey) -> Self {
        Self(key)
    }

    pub fn signature_algorithm(&self) -> Option<Algorithm> {
        match self.0.kty {
            KeyType::Assigned(kty) => match kty {
                iana::KeyType::EC2 => match get_crv(self).unwrap() {
                    EllipticCurve::Ed448 => Some(Algorithm::EdDSA),
                    EllipticCurve::Ed25519 => Some(Algorithm::EdDSA),
                    _ => None,
                },
                iana::KeyType::OKP => match get_crv(self).unwrap() {
                    EllipticCurve::P_256 => Some(Algorithm::ES256),
                    EllipticCurve::P_384 => Some(Algorithm::ES384),
                    EllipticCurve::P_521 => Some(Algorithm::ES512),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }
}

/// Serialize [CoseKey] by serializing the [Value].
impl ser::Serialize for CoseKey {
    #[inline]
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0.clone().to_cbor_value().map_err(ser::Error::custom)?;
        match value {
            Value::Bytes(x) => serializer.serialize_bytes(&x),
            Value::Bool(x) => serializer.serialize_bool(x),
            Value::Text(x) => serializer.serialize_str(x.as_str()),
            Value::Null => serializer.serialize_unit(),

            Value::Tag(tag, ref v) => Tagged::new(Some(tag), v).serialize(serializer),

            Value::Float(x) => {
                let y = x as f32;
                if (y as f64).to_bits() == x.to_bits() {
                    serializer.serialize_f32(y)
                } else {
                    serializer.serialize_f64(x)
                }
            }

            #[allow(clippy::unnecessary_fallible_conversions)]
            Value::Integer(x) => {
                if let Ok(x) = u8::try_from(x) {
                    serializer.serialize_u8(x)
                } else if let Ok(x) = i8::try_from(x) {
                    serializer.serialize_i8(x)
                } else if let Ok(x) = u16::try_from(x) {
                    serializer.serialize_u16(x)
                } else if let Ok(x) = i16::try_from(x) {
                    serializer.serialize_i16(x)
                } else if let Ok(x) = u32::try_from(x) {
                    serializer.serialize_u32(x)
                } else if let Ok(x) = i32::try_from(x) {
                    serializer.serialize_i32(x)
                } else if let Ok(x) = u64::try_from(x) {
                    serializer.serialize_u64(x)
                } else if let Ok(x) = i64::try_from(x) {
                    serializer.serialize_i64(x)
                } else if let Ok(x) = u128::try_from(x) {
                    serializer.serialize_u128(x)
                } else if let Ok(x) = i128::try_from(x) {
                    serializer.serialize_i128(x)
                } else {
                    unreachable!()
                }
            }

            Value::Array(x) => {
                let mut map = serializer.serialize_seq(Some(x.len()))?;

                for v in x {
                    map.serialize_element(&v)?;
                }

                map.end()
            }

            Value::Map(x) => {
                let mut map = serializer.serialize_map(Some(x.len()))?;

                for (k, v) in x {
                    map.serialize_entry(&k, &v)?;
                }

                map.end()
            }
            _ => unimplemented!(),
        }
    }
}

/// Deserialize [CoseKey] by first deserializing the [Value] and then using [coset::CoseSign1::from_cbor_value].
impl<'de> Deserialize<'de> for CoseKey {
    fn deserialize<D>(deserializer: D) -> crate::cose::sign1::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize the input to a CBOR Value
        let value = Value::deserialize(deserializer)?;
        // Convert the CBOR Value to CoseKey
        Ok(CoseKey(
            coset::CoseKey::from_cbor_value(value).map_err(serde::de::Error::custom)?,
        ))
    }
}

impl TryFrom<CoseKey> for EncodedPoint {
    type Error = Error;
    fn try_from(value: CoseKey) -> Result<EncodedPoint, Self::Error> {
        let x = get_x(&value)?.as_bytes().ok_or(Error::EC2MissingX)?;
        match value.0.kty {
            KeyType::Assigned(kty) => match kty {
                iana::KeyType::EC2 => {
                    let x_generic_array = GenericArray::from_slice(x.as_ref());
                    match get_y(&value)? {
                        Value::Bytes(y) => {
                            let y_generic_array = GenericArray::from_slice(y.as_ref());
                            Ok(EncodedPoint::from_affine_coordinates(
                                x_generic_array,
                                y_generic_array,
                                false,
                            ))
                        }
                        Value::Bool(y) => {
                            let mut bytes = x.clone();
                            if *y {
                                bytes.insert(0, 3)
                            } else {
                                bytes.insert(0, 2)
                            }
                            let encoded = EncodedPoint::from_bytes(bytes)
                                .map_err(|_e| Error::InvalidCoseKey)?;
                            Ok(encoded)
                        }
                        _ => Err(Error::InvalidTypeYSign(value.0.params[2].1.clone()))?,
                    }
                }
                iana::KeyType::OKP => {
                    let x_generic_array: GenericArray<_, U8> =
                        GenericArray::clone_from_slice(&x[0..42]);
                    let encoded = EncodedPoint::from_bytes(x_generic_array)
                        .map_err(|_e| Error::InvalidCoseKey)?;
                    Ok(encoded)
                }
                _ => Err(Error::UnsupportedKeyType),
            },
            _ => Err(Error::UnsupportedKeyType),
        }
    }
}

impl From<CoseKey> for CborValue {
    /// # Panics
    ///
    /// If X or Y is missing.
    fn from(key: CoseKey) -> CborValue {
        let mut map = BTreeMap::new();
        let x = get_x(&key)
            .unwrap()
            .as_bytes()
            .ok_or(Error::EC2MissingX)
            .unwrap()
            .clone();
        let y = get_y(&key)
            .unwrap()
            .as_bytes()
            .ok_or(Error::EC2MissingY)
            .unwrap()
            .clone();
        if let KeyType::Assigned(kty) = key.0.kty {
            match kty {
                iana::KeyType::EC2 => {
                    // kty: 1, EC2: 2
                    map.insert(CborValue::Integer(1), CborValue::Integer(2));
                    // crv: -1
                    map.insert(
                        CborValue::Integer(-1),
                        match key.0.params[0].1 {
                            Value::Integer(i) => CborValue::Integer(i.into()),
                            _ => CborValue::Integer(0),
                        },
                    );
                    // x: -2
                    map.insert(CborValue::Integer(-2), CborValue::Bytes(x));
                    // y: -3
                    map.insert(CborValue::Integer(-3), y.into());
                }
                iana::KeyType::OKP => {
                    // kty: 1, OKP: 1
                    map.insert(CborValue::Integer(1), CborValue::Integer(1));
                    // crv: -1
                    map.insert(
                        CborValue::Integer(-1),
                        match key.0.params[0].1 {
                            Value::Integer(i) => CborValue::Integer(i.into()),
                            _ => CborValue::Integer(0),
                        },
                    );
                    // x: -2
                    map.insert(CborValue::Integer(-2), CborValue::Bytes(x));
                }
                _ => {}
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
                    let crv = EllipticCurve::from_i64(crv_id as i64).ok_or(Error::UnknownCurve)?;
                    let y = map
                        .remove(&CborValue::Integer(-3))
                        .ok_or(Error::EC2MissingY)?;
                    let y = if let CborValue::Bytes(y) = y {
                        y
                    } else {
                        Err(Error::InvalidTypeY(y))?
                    };
                    let key = coset::CoseKeyBuilder::new_ec2_pub_key(crv, x, y).build();
                    let key = CoseKey(key);
                    Ok(key)
                }
                (
                    Some(CborValue::Integer(1)),
                    Some(CborValue::Integer(crv_id)),
                    Some(CborValue::Bytes(x)),
                ) => {
                    let crv = EllipticCurve::from_i64(crv_id as i64).ok_or(Error::UnknownCurve)?;
                    let key = coset::CoseKeyBuilder::new_okp_key()
                        .param(iana::Ec2KeyParameter::Crv as i64, Value::from(crv as u64))
                        .param(iana::Ec2KeyParameter::X as i64, Value::Bytes(x))
                        .build();
                    let key = CoseKey(key);
                    Ok(key)
                }
                _ => Err(Error::UnsupportedKeyType),
            }
        } else {
            Err(Error::NotAMap(v))
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
                let key = coset::CoseKeyBuilder::new_ec2_pub_key(
                    into_curve(params.curve.clone().ok_or(Error::UnknownCurve)?)?,
                    x,
                    params
                        .y_coordinate
                        .as_ref()
                        .ok_or(Error::EC2MissingY)?
                        .0
                        .clone(),
                )
                .build();
                let key = CoseKey(key);
                Ok(key)
            }
            ssi_jwk::Params::OKP(params) => {
                let crv = EllipticCurve::from_i64(into_curve(params.curve.clone())? as i64)
                    .ok_or(Error::UnknownCurve)?;
                let key = coset::CoseKeyBuilder::new_okp_key()
                    .param(iana::Ec2KeyParameter::Crv as i64, Value::from(crv as u64))
                    .param(
                        iana::Ec2KeyParameter::X as i64,
                        Value::Bytes(params.public_key.0.clone()),
                    )
                    .build();
                let key = CoseKey(key);
                Ok(key)
            }
            _ => Err(Error::UnsupportedKeyType),
        }
    }
}

fn into_curve(str: String) -> Result<EllipticCurve, Error> {
    Ok(match str.as_str() {
        "P_256" => EllipticCurve::P_256,
        "P_384" => EllipticCurve::P_384,
        "P_521" => EllipticCurve::P_521,
        "Ed448" => EllipticCurve::Ed448,
        "Ed25519" => EllipticCurve::Ed25519,
        "Reserved" => EllipticCurve::Reserved,
        "Secp256k1" => EllipticCurve::Secp256k1,
        "X25519" => EllipticCurve::X25519,
        _ => return Err(Error::UnknownCurve),
    })
}

fn get_x(key: &CoseKey) -> Result<&Value, Error> {
    for (key, value) in &key.0.params {
        match key {
            Label::Int(p) if *p == iana::Ec2KeyParameter::X as i64 => return Ok(value),
            _ => continue,
        }
    }
    Err(Error::EC2MissingX)
}

fn get_y(key: &CoseKey) -> Result<&Value, Error> {
    for (key, value) in &key.0.params {
        match key {
            Label::Int(p) if *p == iana::Ec2KeyParameter::Y as i64 => return Ok(value),
            _ => continue,
        }
    }
    Err(Error::EC2MissingY)
}

fn get_crv(key: &CoseKey) -> Result<EllipticCurve, Error> {
    for item in &key.0.params {
        match item {
            (Label::Int(p), Value::Integer(crv)) if *p == iana::Ec2KeyParameter::Crv as i64 => {
                let crv: i128 = From::from(*crv);
                return EllipticCurve::from_i64(crv as i64).ok_or(Error::UnknownCurve);
            }
            _ => continue,
        }
    }
    Err(Error::EC2MissingX)
}
