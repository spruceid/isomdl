pub use super::FullDate;

use crate::definitions::traits::{FromJson, FromJsonError};
use anyhow::anyhow;
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

#[derive(Debug, Clone)]
pub struct TDate(String);

#[derive(Debug, Clone)]
pub enum TDateOrFullDate {
    TDate(TDate),
    FullDate(FullDate),
}

impl FromJson for TDate {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        let date_str = String::from_json(v)?;

        // 18013-5 asks for dates to be in RFC3339 format with no milliseconds, and with no UTC
        // offset.
        Ok(Self(
            OffsetDateTime::parse(&date_str, &Rfc3339)
                .map_err(|e| anyhow!("date not in RFC3339 format: {}", e))
                .map_err(FromJsonError::Parsing)?
                .to_offset(UtcOffset::UTC)
                .replace_millisecond(0)
                // Unwrap safety: 0 is a valid millisecond.
                .unwrap()
                .format(&Rfc3339)
                // Unwrap safety: it has just been successfully parsed from a RFC3339 formatted string.
                .unwrap(),
        ))
    }
}

impl FromJson for TDateOrFullDate {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        if let Ok(td) = TDate::from_json(v) {
            return Ok(Self::TDate(td));
        }

        if let Ok(fd) = FullDate::from_json(v) {
            return Ok(Self::FullDate(fd));
        }

        Err(anyhow!("could not parse as RFC3339 date-time or full-date").into())
    }
}
