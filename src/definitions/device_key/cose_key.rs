use aes::cipher::consts::U8;
use aes::cipher::generic_array::GenericArray;
use ciborium::Value;
use coset::iana::Algorithm;
use coset::{iana, AsCborValue, KeyType, Label};
use p256::EncodedPoint;
use serde::ser;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::Deserialize;
use serde::Deserializer;
use serde_cbor::tags::Tagged;

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
    InvalidTypeY(Value),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(Value),
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
                iana::KeyType::EC2 => match self.0.params[1].0 {
                    Label::Int(crv) if crv == iana::EllipticCurve::Ed448 as i64 => {
                        Some(Algorithm::EdDSA)
                    }
                    Label::Int(crv) if crv == iana::EllipticCurve::Ed25519 as i64 => {
                        Some(Algorithm::EdDSA)
                    }
                    _ => None,
                },
                iana::KeyType::OKP => match self.0.params[1].0 {
                    Label::Int(crv) if crv == iana::EllipticCurve::P_256 as i64 => {
                        Some(Algorithm::ES256)
                    }
                    Label::Int(crv) if crv == iana::EllipticCurve::P_384 as i64 => {
                        Some(Algorithm::ES384)
                    }
                    Label::Int(crv) if crv == iana::EllipticCurve::P_521 as i64 => {
                        Some(Algorithm::ES512)
                    }
                    Label::Text(_) => None,
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
        let x = value.0.params[1].1.as_bytes().ok_or(Error::EC2MissingX)?;
        let y = value.0.params[2].1.as_bytes().ok_or(Error::EC2MissingY)?;
        match value.0.kty {
            KeyType::Assigned(kty) => match kty {
                iana::KeyType::EC2 => {
                    // todo: EC2Y::SignBit(y)
                    let x_generic_array = GenericArray::from_slice(x.as_ref());
                    let y_generic_array = GenericArray::from_slice(y.as_ref());
                    Ok(EncodedPoint::from_affine_coordinates(
                        x_generic_array,
                        y_generic_array,
                        false,
                    ))
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
