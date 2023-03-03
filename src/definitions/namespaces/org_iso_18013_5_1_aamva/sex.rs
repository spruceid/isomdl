use crate::definitions::traits::{FromJson, FromJsonError, ToCbor};
use serde_cbor::Value as Cbor;
use serde_json::Value as Json;

/// `sex` in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
#[derive(Debug, Clone)]
pub enum Sex {
    Male,
    Female,
    NotApplicable,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unrecognized variant: {0}")]
    Unrecognized(u32),
}

impl From<Sex> for u8 {
    fn from(s: Sex) -> u8 {
        match s {
            Sex::Male => 1,
            Sex::Female => 2,
            Sex::NotApplicable => 9,
        }
    }
}

impl ToCbor for Sex {
    fn to_cbor(self) -> Cbor {
        u8::from(self).into()
    }
}

impl TryFrom<u32> for Sex {
    type Error = Error;

    fn try_from(u: u32) -> Result<Sex, Error> {
        match u {
            1 => Ok(Sex::Male),
            2 => Ok(Sex::Female),
            9 => Ok(Sex::NotApplicable),
            _ => Err(Error::Unrecognized(u)),
        }
    }
}

impl FromJson for Sex {
    fn from_json(v: &Json) -> Result<Self, FromJsonError> {
        u32::from_json(v)?
            .try_into()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
