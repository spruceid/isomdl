use serde::{
    ser::{Error as SerError, Serializer},
    Deserialize, Serialize,
};
use serde_cbor::Value as CborValue;
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
    MissingField(CborValue),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(CborValue),
    #[error("Expected to parse a CBOR text string, received: '{0:?}'")]
    NotATextString(Box<CborValue>),
    #[error("Expected to parse a CBOR tag (number {0}), received: '{1:?}'")]
    NotATag(u64, CborValue),
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
                        $date.to_offset(UtcOffset::UTC).format(&Rfc3339)?,
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
