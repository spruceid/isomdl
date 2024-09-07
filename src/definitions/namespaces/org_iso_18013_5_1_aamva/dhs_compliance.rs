use crate::definitions::traits::{FromJson, FromJsonError, ToCbor};
use crate::cbor::Value as Cbor;
use serde_json::Value as Json;
use std::str::FromStr;

/// `DHS_compliance` in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
#[derive(Debug, Clone)]
pub enum DHSCompliance {
    F,
    N,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unrecognized variant: {0}")]
    Unrecognized(String),
}

impl DHSCompliance {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::F => "F",
            Self::N => "N",
        }
    }
}

impl ToCbor for DHSCompliance {
    fn to_cbor(self) -> Cbor {
        self.to_str().to_string().into()
    }
}

impl FromStr for DHSCompliance {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "F" => Ok(Self::F),
            "N" => Ok(Self::N),
            _ => Err(Error::Unrecognized(s.to_string())),
        }
    }
}

impl FromJson for DHSCompliance {
    fn from_json(v: &Json) -> Result<Self, FromJsonError> {
        String::from_json(v)?
            .parse()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
