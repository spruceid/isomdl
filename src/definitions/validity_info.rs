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
use serde::{
    ser::{Error as SerError, Serializer},
    Deserialize, Serialize,
};
use crate::cbor::Value as CborValue;
use std::collections::BTreeMap;
use time::{
    error::Format as FormatError, error::Parse as ParseError,
    format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "CborValue")]
pub struct ValidityInfo {
    pub signed: OffsetDateTime,
    pub valid_from: OffsetDateTime,
    pub valid_until: OffsetDateTime,
    pub expected_update: Option<OffsetDateTime>,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("When parsing a CBOR map, could not find required field: '{0:?}'")]
    MissingField(ciborium::Value),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(ciborium::Value),
    #[error("Expected to parse a CBOR text string, received: '{0:?}'")]
    NotATextString(Box<ciborium::Value>),
    #[error("Expected to parse a CBOR tag (number {0}), received: '{1:?}'")]
    NotATag(u64, ciborium::Value),
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
                let key = ciborium::Value::Text(String::from($name));
                let value = ciborium::Value::Tag(
                    0,
                    Box::new(ciborium::Value::Text(
                        $date
                            .replace_millisecond(0)?
                            .to_offset(UtcOffset::UTC)
                            .format(&Rfc3339)?,
                    )),
                );
                $map.push((key, value));
            };
            ($map:ident, $struct: ident, $field:ident, $name:literal) => {
                let date = $struct.$field;
                insert_date!($map, date, $name)
            };
        }

        let mut map = vec![];

        insert_date!(map, v, signed, "signed");
        insert_date!(map, v, valid_from, "validFrom");
        insert_date!(map, v, valid_until, "validUntil");

        if let Some(expected_update) = v.expected_update {
            insert_date!(map, expected_update, "expectedUpdate");
        }

        Ok(ciborium::Value::Map(map).into())
    }
}

impl TryFrom<CborValue> for ValidityInfo {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<ValidityInfo> {
        if let ciborium::Value::Map(map) = v.0 {
            let mut map = map.into_iter().map(|(k, v)| (k.into(), v.into())).collect::<BTreeMap<CborValue, CborValue>>();
            macro_rules! extract_date {
                ($map:ident, $name:literal) => {{
                    let key = CborValue(ciborium::Value::Text(String::from($name)));
                    $map.remove(&key)
                        .ok_or(Error::MissingField(key.into()))
                        .and_then(cbor_to_datetime)?
                }};
            }

            let signed = extract_date!(map, "signed");
            let valid_from = extract_date!(map, "validFrom");
            let valid_until = extract_date!(map, "validUntil");

            let expected_update_key: CborValue = ciborium::Value::Text(String::from("expectedUpdate")).into();
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
            Err(Error::NotAMap(v.into()))
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
    if let ciborium::Value::Tag(0, inner) = v.0 {
        if let ciborium::Value::Text(date_str) = inner.as_ref() {
            Ok(OffsetDateTime::parse(date_str, &Rfc3339)?)
        } else {
            Err(Error::NotATextString(inner))
        }
    } else {
        Err(Error::NotATag(0, v.into()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn roundtrip() {
        let cbor = hex::decode("A3667369676E6564C074323032302D30312D30315430303A30303A30305A6976616C696446726F6DC074323032302D30312D30315430303A30303A30305A6A76616C6964556E74696CC074323032302D30312D30315430303A30303A30305A").unwrap();
        let validity_info: ValidityInfo = crate::cbor::from_slice(&cbor).unwrap();
        let roundtripped = crate::cbor::to_vec(&validity_info).unwrap();
        assert_eq!(cbor, roundtripped);
    }

    // Test that microseconds are trimmed.
    #[test]
    fn trim() {
        let cbor = hex::decode("A3667369676E6564C07818323032302D30312D30315430303A30303A30302E3130315A6976616C696446726F6DC0781B323032302D30312D30315430303A30303A30302E3131323231395A6A76616C6964556E74696CC0781E323032302D30312D30315430303A30303A30302E3939393939393939395A").unwrap();
        let validity_info: ValidityInfo = crate::cbor::from_slice(&cbor).unwrap();
        let roundtripped = crate::cbor::to_vec(&validity_info).unwrap();
        let trimmed = hex::decode("A3667369676E6564C074323032302D30312D30315430303A30303A30305A6976616C696446726F6DC074323032302D30312D30315430303A30303A30305A6A76616C6964556E74696CC074323032302D30312D30315430303A30303A30305A").unwrap();
        assert_eq!(trimmed, roundtripped);
    }
}
