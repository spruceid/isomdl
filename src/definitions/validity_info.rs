//! This module contains the definition of the [ValidityInfo] struct and related error types.
//!
//! The [ValidityInfo] struct represents information about the validity of a certain entity.  
//! It contains fields such as `signed`, `valid_from`, `valid_until`, and `expected_update`.
//!
//! # Errors
//!
//! The [Error] enum represents various errors that can occur when working with [ValidityInfo] objects.
//!
//! # Serialization and Deserialization
//!
//! The [ValidityInfo] struct implements the [Serialize] and [Deserialize] traits from the [serde] crate,
//! allowing it to be easily serialized and deserialized to and from CBOR format.
//!
//! # Conversion to and from CBOR
//!
//! The [ValidityInfo] struct also provides implementations of the [TryFrom] trait for converting
//! to and from [CborValue], which is a type provided by the [serde_cbor] crate for representing CBOR values.  
//! These implementations allow you to convert [ValidityInfo] objects to `CBOR` format and vice versa.
//!
//! # Dependencies
//!
//! This module depends on the following external crates:
//!
//! - [serde]: Provides the serialization and deserialization traits and macros.
//! - [serde_cbor]: Provides the `CBOR` serialization and deserialization functionality.
//! - [std::collections::BTreeMap]: Provides the [BTreeMap] type for storing key-value pairs in a sorted order.
//! - [time]: Provides date and time manipulation functionality.
//! - [thiserror]: Provides the [thiserror::Error] trait for defining custom error types.

use crate::cbor::CborValue;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use serde::de::Error as SerdeError;
use serde::{
    ser::{Error as SerError, Serializer},
    Deserialize, Deserializer, Serialize,
};
use std::collections::BTreeMap;
use std::fmt::Debug;
use time::{
    error::Format as FormatError, error::Parse as ParseError,
    format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset,
};

#[derive(Clone, Debug)]
pub struct ValidityInfo {
    /// Deserialize [CoseSign1] by first deserializing the [Value] and then using [coset::CoseSign1::from_cbor_value].
    pub signed: OffsetDateTime,
    pub valid_from: OffsetDateTime,
    pub valid_until: OffsetDateTime,
    pub expected_update: Option<OffsetDateTime>,
}

impl CborSerializable for ValidityInfo {}
impl AsCborValue for ValidityInfo {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let cbor_value: CborValue = value.into();
        cbor_value.try_into().map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "cannot decode ValidityInfo".to_string(),
            ))
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let cbor_value: CborValue = self
            .try_into()
            .map_err(|_| coset::CoseError::EncodeFailed)?;
        Ok(cbor_value.into())
    }
}

impl<'de> Deserialize<'de> for ValidityInfo {
    fn deserialize<D>(deserializer: D) -> crate::cose::sign1::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        macro_rules! extract_date {
            ($map:ident, $name:literal) => {{
                let key = CborValue::Text(String::from($name));
                $map.remove(&key)
                    .ok_or(Error::MissingField(key))
                    .and_then(cbor_to_datetime)
                    .map_err(|_| D::Error::custom("cannot deserialize"))?
            }};
        }

        let value = Value::deserialize(deserializer)?;
        let value: CborValue = value.into();
        let mut map = value
            .into_map()
            .map_err(|_| D::Error::custom("not a map"))?;
        let signed = extract_date!(map, "signed");
        let valid_from = extract_date!(map, "validFrom");
        let valid_until = extract_date!(map, "validUntil");

        let expected_update_key = CborValue::Text(String::from("expectedUpdate"));
        let expected_update = map
            .remove(&expected_update_key)
            .map(cbor_to_datetime)
            .transpose()
            .map_err(|_| D::Error::custom("cannot deserialize"))?;
        Ok(ValidityInfo {
            signed,
            valid_from,
            valid_until,
            expected_update,
        })
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("When parsing a CBOR map, could not find required field: '{0:?}'")]
    MissingField(CborValue),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(CborValue),
    #[error("Expected to parse a CBOR text string, received: '{0:?}'")]
    NotATextString(Box<CborValue>),
    #[error("Expected to parse a CBOR tag (number {0}), received: '{1:?}'")]
    NotATag(u64, CborValue),
    #[error(transparent)]
    OutOfRange(#[from] time::error::ComponentRange),
    #[error("Failed to format date string as rfc3339 date: {0}")]
    UnableToFormatDate(#[from] FormatError),
    #[error("Failed to parse date string as rfc3339 date: {0}")]
    UnableToParseDate(#[from] ParseError),
}

impl TryFrom<ValidityInfo> for CborValue {
    type Error = Error;

    fn try_from(v: ValidityInfo) -> Result<CborValue> {
        macro_rules! insert_date {
            ($map:ident, $date:ident, $name:literal) => {
                let key = CborValue::Text(String::from($name));
                let value = CborValue::Tag(
                    0,
                    Box::new(CborValue::Text(
                        $date
                            .replace_millisecond(0)?
                            .to_offset(UtcOffset::UTC)
                            .format(&Rfc3339)?,
                    )),
                );
                $map.insert(key, value);
            };
            ($map:ident, $struct: ident, $field:ident, $name:literal) => {
                let date = $struct.$field;
                insert_date!($map, date, $name)
            };
        }

        let mut map = BTreeMap::new();

        insert_date!(map, v, signed, "signed");
        insert_date!(map, v, valid_from, "validFrom");
        insert_date!(map, v, valid_until, "validUntil");

        if let Some(expected_update) = v.expected_update {
            insert_date!(map, expected_update, "expectedUpdate");
        }

        Ok(CborValue::Map(map))
    }
}

impl TryFrom<CborValue> for ValidityInfo {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<ValidityInfo> {
        if let CborValue::Map(mut map) = v {
            macro_rules! extract_date {
                ($map:ident, $name:literal) => {{
                    let key = CborValue::Text(String::from($name));
                    $map.remove(&key)
                        .ok_or(Error::MissingField(key))
                        .and_then(cbor_to_datetime)?
                }};
            }

            let signed = extract_date!(map, "signed");
            let valid_from = extract_date!(map, "validFrom");
            let valid_until = extract_date!(map, "validUntil");

            let expected_update_key = CborValue::Text(String::from("expectedUpdate"));
            let expected_update = map
                .remove(&expected_update_key)
                .map(cbor_to_datetime)
                .transpose()?;

            Ok(Self {
                signed,
                valid_from,
                valid_until,
                expected_update,
            })
        } else {
            Err(Error::NotAMap(v))
        }
    }
}

impl Serialize for ValidityInfo {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        CborValue::try_from(self.clone())
            .map_err(S::Error::custom)?
            .serialize(s)
    }
}

fn cbor_to_datetime(v: CborValue) -> Result<OffsetDateTime> {
    if let CborValue::Tag(0, inner) = v {
        if let CborValue::Text(date_str) = inner.as_ref() {
            Ok(OffsetDateTime::parse(date_str, &Rfc3339)?)
        } else {
            Err(Error::NotATextString(inner))
        }
    } else {
        Err(Error::NotATag(0, v))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn roundtrip() {
        let cbor = hex::decode("A3667369676E6564C074323032302D30312D30315430303A30303A30305A6976616C696446726F6DC074323032302D30312D30315430303A30303A30305A6A76616C6964556E74696CC074323032302D30312D30315430303A30303A30305A").unwrap();
        let validity_info = ValidityInfo::from_slice(&cbor).unwrap();
        let roundtripped = validity_info.to_vec().unwrap();
        assert_eq!(cbor, roundtripped);
    }

    // Test that microseconds are trimmed.
    #[test]
    fn trim() {
        let cbor = hex::decode("A3667369676E6564C07818323032302D30312D30315430303A30303A30302E3130315A6976616C696446726F6DC0781B323032302D30312D30315430303A30303A30302E3131323231395A6A76616C6964556E74696CC0781E323032302D30312D30315430303A30303A30302E3939393939393939395A").unwrap();
        let validity_info = ValidityInfo::from_slice(&cbor).unwrap();
        let roundtripped = validity_info.to_vec().unwrap();
        let trimmed = hex::decode("A3667369676E6564C074323032302D30312D30315430303A30303A30305A6976616C696446726F6DC074323032302D30312D30315430303A30303A30305A6A76616C6964556E74696CC074323032302D30312D30315430303A30303A30305A").unwrap();
        assert_eq!(trimmed, roundtripped);
    }
}
