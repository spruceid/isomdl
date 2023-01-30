use crate::definitions::traits::{FromJson, FromJsonError};
use serde_json::Value;

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

impl FromJson for CountyCode {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
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
    return Ok((first, second, third));
}
