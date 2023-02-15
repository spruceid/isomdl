use crate::definitions::traits::{FromJson, FromJsonError, ToCbor};
use serde_cbor::Value as Cbor;
use serde_json::Value as Json;

/// `EDL_indicator` in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
#[derive(Debug, Clone)]
pub enum EDLIndicator {
    DriversLicense,
    IdentificationCard,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unrecognized variant: {0}")]
    Unrecognized(u32),
}

impl From<EDLIndicator> for u8 {
    fn from(s: EDLIndicator) -> u8 {
        match s {
            EDLIndicator::DriversLicense => 1,
            EDLIndicator::IdentificationCard => 2,
        }
    }
}

impl ToCbor for EDLIndicator {
    fn to_cbor(self) -> Cbor {
        u8::from(self).into()
    }
}

impl TryFrom<u32> for EDLIndicator {
    type Error = Error;

    fn try_from(u: u32) -> Result<EDLIndicator, Error> {
        match u {
            1 => Ok(EDLIndicator::DriversLicense),
            2 => Ok(EDLIndicator::IdentificationCard),
            _ => Err(Error::Unrecognized(u)),
        }
    }
}

impl FromJson for EDLIndicator {
    fn from_json(v: &Json) -> Result<Self, FromJsonError> {
        u32::from_json(v)?
            .try_into()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
