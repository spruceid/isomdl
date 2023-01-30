use crate::definitions::traits::{FromJson, FromJsonError};
use serde_json::Value;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum NameSuffix {
    Junior,
    Senior,
    First,
    FirstNumeral,
    Second,
    SecondNumeral,
    Third,
    ThirdNumeral,
    Fourth,
    FourthNumeral,
    Fifth,
    FifthNumeral,
    Sixth,
    SixthNumeral,
    Seventh,
    SeventhNumeral,
    Eighth,
    EighthNumeral,
    Ninth,
    NinthNumeral,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unrecognized variant: {0}")]
    Unrecognized(String),
}

impl NameSuffix {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Junior => "JR",
            Self::Senior => "SR",
            Self::First => "1ST",
            Self::FirstNumeral => "I",
            Self::Second => "2ND",
            Self::SecondNumeral => "II",
            Self::Third => "3RD",
            Self::ThirdNumeral => "III",
            Self::Fourth => "4TH",
            Self::FourthNumeral => "IV",
            Self::Fifth => "5TH",
            Self::FifthNumeral => "V",
            Self::Sixth => "6TH",
            Self::SixthNumeral => "VI",
            Self::Seventh => "7TH",
            Self::SeventhNumeral => "VII",
            Self::Eighth => "8TH",
            Self::EighthNumeral => "VIII",
            Self::Ninth => "9TH",
            Self::NinthNumeral => "IX",
        }
    }
}

impl FromStr for NameSuffix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "JR" => Ok(Self::Junior),
            "SR" => Ok(Self::Senior),
            "1ST" => Ok(Self::First),
            "I" => Ok(Self::FirstNumeral),
            "2ND" => Ok(Self::Second),
            "II" => Ok(Self::SecondNumeral),
            "3RD" => Ok(Self::Third),
            "III" => Ok(Self::ThirdNumeral),
            "4TH" => Ok(Self::Fourth),
            "IV" => Ok(Self::FourthNumeral),
            "5TH" => Ok(Self::Fifth),
            "V" => Ok(Self::FifthNumeral),
            "6TH" => Ok(Self::Sixth),
            "VI" => Ok(Self::SixthNumeral),
            "7TH" => Ok(Self::Seventh),
            "VII" => Ok(Self::SeventhNumeral),
            "8TH" => Ok(Self::Eighth),
            "VIII" => Ok(Self::EighthNumeral),
            "9TH" => Ok(Self::Ninth),
            "IX" => Ok(Self::NinthNumeral),
            _ => Err(Error::Unrecognized(s.to_string())),
        }
    }
}

impl FromJson for NameSuffix {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        String::from_json(v)?
            .parse()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
