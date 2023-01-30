use crate::definitions::traits::{FromJson, FromJsonError};
use serde_json::Value;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum RaceAndEthnicity {
    AI,
    AP,
    BK,
    H,
    O,
    U,
    W,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unrecognized variant: {0}")]
    Unrecognized(String),
}

impl RaceAndEthnicity {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::AI => "AI",
            Self::AP => "AP",
            Self::BK => "BK",
            Self::H => "H",
            Self::O => "O",
            Self::U => "U",
            Self::W => "W",
        }
    }
}

impl FromStr for RaceAndEthnicity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "AI" => Ok(Self::AI),
            "AP" => Ok(Self::AP),
            "BK" => Ok(Self::BK),
            "H" => Ok(Self::H),
            "O" => Ok(Self::O),
            "U" => Ok(Self::U),
            "W" => Ok(Self::W),
            _ => Err(Error::Unrecognized(s.to_string())),
        }
    }
}

impl FromJson for RaceAndEthnicity {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        String::from_json(v)?
            .parse()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
