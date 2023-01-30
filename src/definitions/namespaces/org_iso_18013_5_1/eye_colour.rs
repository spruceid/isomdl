use crate::definitions::traits::{FromJson,FromJsonError};
use serde_json::Value;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum EyeColour {
    Black,
    Blue,
    Brown,
    Dichromatic,
    Grey,
    Green,
    Hazel,
    Maroon,
    Pink,
    Unknown,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unrecognized variant: {0}")]
    Unrecognized(String)
}

impl EyeColour {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Black => "black",
            Self::Blue => "blue",
            Self::Brown => "brown",
            Self::Dichromatic => "dichromatic",
            Self::Grey => "grey",
            Self::Green => "green",
            Self::Hazel => "hazel",
            Self::Maroon => "maroon",
            Self::Pink => "pink",
            Self::Unknown => "unknown",
        }
    }
}

impl FromStr for EyeColour {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "black" => Ok(Self::Black),
            "blue" => Ok(Self::Blue),
            "brown" => Ok(Self::Brown),
            "dichromatic" => Ok(Self::Dichromatic),
            "grey" => Ok(Self::Grey),
            "green" => Ok(Self::Green),
            "hazel" => Ok(Self::Hazel),
            "maroon" => Ok(Self::Maroon),
            "pink" => Ok(Self::Pink),
            "unknown" => Ok(Self::Unknown),
            _ => Err(Error::Unrecognized(s.to_string()))
        }
    }
}

impl FromJson for EyeColour {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        String::from_json(v)?
            .parse()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
