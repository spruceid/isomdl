use chrono::{format::ParseError as ChronoParseError, DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "Value", into = "Value")]
pub struct ValidityInfo {
    signed: DateTime<Utc>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    expected_update: Option<DateTime<Utc>>,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("When parsing a CBOR map, could not find required field: '{0:?}'")]
    MissingField(Value),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(Value),
    #[error("Expected to parse a CBOR text string, received: '{0:?}'")]
    NotATextString(Box<Value>),
    #[error("Expected to parse a CBOR tag (number {0}), received: '{1:?}'")]
    NotATag(u64, Value),
    #[error("Failed to parse date string as rfc3339 date: {0}")]
    UnableToParseDate(ChronoParseError),
}

impl From<ValidityInfo> for Value {
    fn from(v: ValidityInfo) -> Value {
        let mut map = BTreeMap::new();

        let signed_key = Value::Text(String::from("signed"));
        let signed_value = Value::Tag(0, Box::new(Value::Text(v.signed.to_rfc3339())));
        map.insert(signed_key, signed_value);

        let valid_from_key = Value::Text(String::from("validFrom"));
        let valid_from_value = Value::Tag(0, Box::new(Value::Text(v.valid_from.to_rfc3339())));
        map.insert(valid_from_key, valid_from_value);

        let valid_until_key = Value::Text(String::from("validUntil"));
        let valid_until_value = Value::Tag(0, Box::new(Value::Text(v.valid_until.to_rfc3339())));
        map.insert(valid_until_key, valid_until_value);

        if let Some(expected_update) = v.expected_update {
            let expected_update_key = Value::Text(String::from("expectedUpdate"));
            let expected_update_value =
                Value::Tag(0, Box::new(Value::Text(expected_update.to_rfc3339())));
            map.insert(expected_update_key, expected_update_value);
        }

        Value::Map(map)
    }
}

impl TryFrom<Value> for ValidityInfo {
    type Error = Error;

    fn try_from(v: Value) -> Result<ValidityInfo> {
        if let Value::Map(mut map) = v {
            let signed_key = Value::Text(String::from("signed"));
            let signed = map
                .remove(&signed_key)
                .ok_or(Error::MissingField(signed_key))
                .and_then(cbor_to_datetime)?;
            let valid_from_key = Value::Text(String::from("validFrom"));
            let valid_from = map
                .remove(&valid_from_key)
                .ok_or(Error::MissingField(valid_from_key))
                .and_then(cbor_to_datetime)?;
            let valid_until_key = Value::Text(String::from("validUntil"));
            let valid_until = map
                .remove(&valid_until_key)
                .ok_or(Error::MissingField(valid_until_key))
                .and_then(cbor_to_datetime)?;
            let expected_update_key = Value::Text(String::from("expectedUpdate"));
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

fn cbor_to_datetime(v: Value) -> Result<DateTime<Utc>> {
    if let Value::Tag(0, inner) = v {
        if let Value::Text(date_str) = inner.as_ref() {
            DateTime::parse_from_rfc3339(date_str)
                .map(Into::into)
                .map_err(Error::UnableToParseDate)
        } else {
            Err(Error::NotATextString(inner))
        }
    } else {
        Err(Error::NotATag(0, v))
    }
}
