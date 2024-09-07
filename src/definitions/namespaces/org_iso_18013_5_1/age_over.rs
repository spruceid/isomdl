use crate::cbor::Value as Cbor;
use crate::definitions::traits::{FromJson, FromJsonError, FromJsonMap, ToNamespaceMap};
use serde_json::{Map, Value as Json};
use std::{collections::BTreeMap, ops::Deref};

/// `age_over_xx` in the org.iso.18013.5.1 namespace.
#[derive(Debug, Clone)]
pub struct AgeOver(BTreeMap<Age, bool>);

#[derive(Debug, Clone, Ord, Eq, PartialOrd, PartialEq)]
pub struct Age(char, char);

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("{0} is greater than the maximum age of 99")]
    TooLarge(u8),
}

impl TryFrom<u8> for Age {
    type Error = Error;

    fn try_from(u: u8) -> Result<Age, Error> {
        let s = format!("{u:0>2}");
        to_age(&s).ok_or(Error::TooLarge(u))
    }
}

impl Deref for AgeOver {
    type Target = BTreeMap<Age, bool>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromJsonMap for AgeOver {
    fn from_map(m: &Map<String, Json>) -> Result<Self, FromJsonError> {
        m.iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("age_over_")
                    .and_then(to_age)
                    .map(|k| Ok((k, bool::from_json(v)?)))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl ToNamespaceMap for AgeOver {
    fn to_ns_map(self) -> BTreeMap<String, Cbor> {
        self.0
            .into_iter()
            .map(|(Age(x, y), v)| (format!("age_over_{x}{y}"), ciborium::Value::Bool(v).into()))
            .collect()
    }
}

fn to_age(s: &str) -> Option<Age> {
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
    Some(Age(first, second))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parsing() {
        assert!(Age::try_from(1).unwrap() == Age('0', '1'));
        assert!(Age::try_from(99).unwrap() == Age('9', '9'));
        assert!(Age::try_from(100).is_err());
    }

    #[test]
    fn cmp() {
        assert!(Age::try_from(1).unwrap() < Age::try_from(2).unwrap());
        assert!(Age::try_from(9).unwrap() < Age::try_from(10).unwrap());
    }
}
