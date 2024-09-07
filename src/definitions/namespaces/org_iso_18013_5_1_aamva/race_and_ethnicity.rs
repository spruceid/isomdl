use crate::definitions::traits::{FromJson, FromJsonError, ToCbor};
use crate::cbor::Value as Cbor;
use serde_json::Value as Json;
use std::str::FromStr;

/// `race_ethnicity` in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
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

impl ToCbor for RaceAndEthnicity {
    fn to_cbor(self) -> Cbor {
        self.to_str().to_string().into()
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
    fn from_json(v: &Json) -> Result<Self, FromJsonError> {
        String::from_json(v)?
            .parse()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
