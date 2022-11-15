use anyhow::Error;
use serde_cbor::Value;
use std::str::FromStr;
use time::{format_description::FormatItem, macros::format_description, Date};

const FORMAT: &[FormatItem<'static>] = format_description!("[year]-[month]-[day]");

#[derive(Clone, Debug)]
pub struct FullDate(Date);

impl From<FullDate> for Value {
    fn from(d: FullDate) -> Value {
        Value::Tag(
            1004,
            Box::new(Value::Text(format!(
                "{}-{}-{}",
                d.0.year(),
                <u8>::from(d.0.month()),
                d.0.day()
            ))),
        )
    }
}

impl FromStr for FullDate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(FullDate(Date::parse(s, FORMAT)?))
    }
}
