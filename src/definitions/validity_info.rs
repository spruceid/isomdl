use chrono::{format::ParseError as ChronoParseError, DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "CborValue", into = "CborValue")]
pub struct ValidityInfo {
    pub signed: DateTime<Utc>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_update: Option<DateTime<Utc>>,
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
    #[error("Failed to parse date string as rfc3339 date: {0}")]
    UnableToParseDate(ChronoParseError),
}

impl From<ValidityInfo> for CborValue {
    fn from(v: ValidityInfo) -> CborValue {
        let mut map = BTreeMap::new();

        let signed_key = CborValue::Text(String::from("signed"));
        let signed_value = CborValue::Tag(0, Box::new(CborValue::Text(v.signed.to_rfc3339())));
        map.insert(signed_key, signed_value);

        let valid_from_key = CborValue::Text(String::from("validFrom"));
        let valid_from_value =
            CborValue::Tag(0, Box::new(CborValue::Text(v.valid_from.to_rfc3339())));
        map.insert(valid_from_key, valid_from_value);

        let valid_until_key = CborValue::Text(String::from("validUntil"));
        let valid_until_value =
            CborValue::Tag(0, Box::new(CborValue::Text(v.valid_until.to_rfc3339())));
        map.insert(valid_until_key, valid_until_value);

        if let Some(expected_update) = v.expected_update {
            let expected_update_key = CborValue::Text(String::from("expectedUpdate"));
            let expected_update_value =
                CborValue::Tag(0, Box::new(CborValue::Text(expected_update.to_rfc3339())));
            map.insert(expected_update_key, expected_update_value);
        }

        CborValue::Map(map)
    }
}

impl TryFrom<CborValue> for ValidityInfo {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<ValidityInfo> {
        if let CborValue::Map(mut map) = v {
            let signed_key = CborValue::Text(String::from("signed"));
            let signed = map
                .remove(&signed_key)
                .ok_or(Error::MissingField(signed_key))
                .and_then(cbor_to_datetime)?;
            let valid_from_key = CborValue::Text(String::from("validFrom"));
            let valid_from = map
                .remove(&valid_from_key)
                .ok_or(Error::MissingField(valid_from_key))
                .and_then(cbor_to_datetime)?;
            let valid_until_key = CborValue::Text(String::from("validUntil"));
            let valid_until = map
                .remove(&valid_until_key)
                .ok_or(Error::MissingField(valid_until_key))
                .and_then(cbor_to_datetime)?;
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

fn cbor_to_datetime(v: CborValue) -> Result<DateTime<Utc>> {
    if let CborValue::Tag(0, inner) = v {
        if let CborValue::Text(date_str) = inner.as_ref() {
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
