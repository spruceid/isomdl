use crate::cbor::CborValue;
use crate::definitions::traits::{FromJson, FromJsonError, ToCbor};
use serde_json::Value as Json;

/// `county_code` in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
#[derive(Debug, Clone)]
pub struct CountyCode((char, char, char));

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("expected a digit, found '{0}'")]
    InvalidCharacter(char),
    #[error("too short, county code must be three digits")]
    TooShort,
    #[error("too long, county code must be three digits")]
    TooLong,
}

impl ToCbor for CountyCode {
    fn to_cbor(self) -> CborValue {
        let CountyCode((a, b, c)) = self;
        format!("{a}{b}{c}").into()
    }
}

impl FromJson for CountyCode {
    fn from_json(v: &Json) -> Result<Self, FromJsonError> {
        String::from_json(v).and_then(|s| {
            to_treble_digits(&s)
                .map(Self)
                .map_err(Into::into)
                .map_err(FromJsonError::Parsing)
        })
    }
}

fn to_treble_digits(s: &str) -> Result<(char, char, char), Error> {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(d @ '0'..='9') => d,
        Some(c) => return Err(Error::InvalidCharacter(c)),
        _ => return Err(Error::TooShort),
    };
    let second = match chars.next() {
        Some(d @ '0'..='9') => d,
        Some(c) => return Err(Error::InvalidCharacter(c)),
        _ => return Err(Error::TooShort),
    };
    let third = match chars.next() {
        Some(d @ '0'..='9') => d,
        Some(c) => return Err(Error::InvalidCharacter(c)),
        _ => return Err(Error::TooShort),
    };
    if chars.next().is_some() {
        return Err(Error::TooLong);
    }
    Ok((first, second, third))
}
