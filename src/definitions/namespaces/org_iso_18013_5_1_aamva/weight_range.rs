use crate::definitions::traits::{FromJson, FromJsonError};
use serde_json::Value;

/// `weight_range` in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
#[derive(Debug, Clone)]
pub enum WeightRange {
    Zero,
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    Nine,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unrecognized variant: {0}")]
    Unrecognized(u32),
}

impl From<WeightRange> for u8 {
    fn from(s: WeightRange) -> u8 {
        match s {
            WeightRange::Zero => 0,
            WeightRange::One => 1,
            WeightRange::Two => 2,
            WeightRange::Three => 3,
            WeightRange::Four => 4,
            WeightRange::Five => 5,
            WeightRange::Six => 6,
            WeightRange::Seven => 7,
            WeightRange::Eight => 8,
            WeightRange::Nine => 9,
        }
    }
}

impl TryFrom<u32> for WeightRange {
    type Error = Error;

    fn try_from(u: u32) -> Result<WeightRange, Error> {
        match u {
            0 => Ok(Self::Zero),
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            4 => Ok(Self::Four),
            5 => Ok(Self::Five),
            6 => Ok(Self::Six),
            7 => Ok(Self::Seven),
            8 => Ok(Self::Eight),
            9 => Ok(Self::Nine),
            _ => Err(Error::Unrecognized(u)),
        }
    }
}

impl FromJson for WeightRange {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        u32::from_json(v)?
            .try_into()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}
