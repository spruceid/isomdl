use ciborium::Value;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::Serialize;
use serde_cbor::tags::Tagged;

use crate::cose::mac0;

pub(crate) fn serialize<S: serde::Serializer>(
    value: Value,
    tag: Option<u64>,
    serializer: S,
) -> mac0::Result<S::Ok, S::Error> {
    if let Some(tag) = tag {
        return Tagged::new(Some(tag), value).serialize(serializer);
    }
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
