use crate::definitions::traits::{FromJson, FromJsonError, FromMap};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, ops::Deref};

#[derive(Debug, Clone)]
pub struct AgeOver(BTreeMap<(char, char), bool>);

impl Deref for AgeOver {
    type Target = BTreeMap<(char, char), bool>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromMap for AgeOver {
    fn from_map(m: &Map<String, Value>) -> Result<Self, FromJsonError> {
        m.iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("age_over_")
                    .and_then(to_double_digits)
                    .map(|k| Ok((k, bool::from_json(v)?)))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

fn to_double_digits(s: &str) -> Option<(char, char)> {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(d @ '0'..='9') => d,
        _ => return None,
    };
    let second = match chars.next() {
        Some(d @ '0'..='9') => d,
        _ => return None,
    };
    if chars.next().is_some() {
        return None;
    }
    Some((first, second))
}
