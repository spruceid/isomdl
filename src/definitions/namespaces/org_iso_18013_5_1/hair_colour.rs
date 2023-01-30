use crate::definitions::traits::{FromJson, FromJsonError};
use serde_json::Value;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum HairColour {
    Bald,
    Black,
    Blond,
    Brown,
    Grey,
    Red,
    Auburn,
    Sandy,
    White,
    Unknown,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unrecognized variant: {0}")]
    Unrecognized(String),
}

impl HairColour {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Bald => "bald",
            Self::Black => "black",
            Self::Blond => "blond",
            Self::Brown => "brown",
            Self::Grey => "grey",
            Self::Red => "red",
            Self::Auburn => "auburn",
            Self::Sandy => "sandy",
            Self::White => "white",
            Self::Unknown => "unknown",
        }
    }
}

impl FromStr for HairColour {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "bald" => Ok(Self::Bald),
            "black" => Ok(Self::Black),
            "blond" => Ok(Self::Blond),
            "brown" => Ok(Self::Brown),
            "grey" => Ok(Self::Grey),
            "red" => Ok(Self::Red),
            "auburn" => Ok(Self::Auburn),
            "sandy" => Ok(Self::Sandy),
            "white" => Ok(Self::White),
            "unknown" => Ok(Self::Unknown),
            _ => Err(Error::Unrecognized(s.to_string())),
        }
    }
}

impl FromJson for HairColour {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        String::from_json(v)?
            .parse()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
