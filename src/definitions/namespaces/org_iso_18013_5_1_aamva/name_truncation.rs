use crate::definitions::traits::{FromJson, FromJsonError};
use serde_json::Value;
use std::str::FromStr;

/// `name_truncation` in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
#[derive(Debug, Clone)]
pub enum NameTruncation {
    Truncated,
    NotTruncated,
    Unknown,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unrecognized variant: {0}")]
    Unrecognized(String),
}

impl NameTruncation {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Truncated => "T",
            Self::NotTruncated => "N",
            Self::Unknown => "U",
        }
    }
}

impl FromStr for NameTruncation {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "T" => Ok(Self::Truncated),
            "N" => Ok(Self::NotTruncated),
            "U" => Ok(Self::Unknown),
            _ => Err(Error::Unrecognized(s.to_string())),
        }
    }
}

impl FromJson for NameTruncation {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        String::from_json(v)?
            .parse()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
