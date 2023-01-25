use anyhow::Error;
use serde_cbor::Value;
use std::{fmt, str::FromStr};
use time::{format_description::FormatItem, macros::format_description, Date};

const FORMAT: &[FormatItem<'static>] = format_description!("[year]-[month]-[day]");

/// `full-date` as defined in RFC3339.
#[derive(Clone, Debug)]
pub struct FullDate(Date);

impl From<FullDate> for Value {
    fn from(d: FullDate) -> Value {
        Value::Tag(1004, Box::new(Value::Text(d.to_string())))
    }
}

impl fmt::Display for FullDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}-{:0>2}-{:0>2}",
            self.0.year(),
            <u8>::from(self.0.month()),
            self.0.day()
        )
    }
}

impl FromStr for FullDate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(FullDate(Date::parse(s, FORMAT)?))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fulldate_str_roundtrip() {
        const DATESTR_LO: &str = "2000-02-01";
        let fulldate = FullDate::from_str(DATESTR_LO).expect("unable to parse datestr");
        assert_eq!(DATESTR_LO, fulldate.to_string());
        const DATESTR_HI: &str = "2000-12-30";
        let fulldate = FullDate::from_str(DATESTR_HI).expect("unable to parse datestr");
        assert_eq!(DATESTR_HI, fulldate.to_string());
    }
}
