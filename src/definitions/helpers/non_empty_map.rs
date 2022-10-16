use serde::{Deserialize, Serialize};
use std::{collections::HashMap, hash::Hash, ops::Deref};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(try_from = "HashMap<K, V>", into = "HashMap<K, V>")]
pub struct NonEmptyMap<K: Hash + Eq + Clone, V: Clone>(HashMap<K, V>);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot construct a non-empty vec from an empty vec")]
    Empty,
}

impl<K: Hash + Eq + Clone, V: Clone> TryFrom<HashMap<K, V>> for NonEmptyMap<K, V> {
    type Error = Error;

    fn try_from(m: HashMap<K, V>) -> Result<NonEmptyMap<K, V>, Error> {
        if m.is_empty() {
            return Err(Error::Empty);
        }
        Ok(NonEmptyMap(m))
    }
}

impl<K: Hash + Eq + Clone, V: Clone> From<NonEmptyMap<K, V>> for HashMap<K, V> {
    fn from(NonEmptyMap(m): NonEmptyMap<K, V>) -> HashMap<K, V> {
        m
    }
}

impl<K: Hash + Eq + Clone, V: Clone> AsRef<HashMap<K, V>> for NonEmptyMap<K, V> {
    fn as_ref(&self) -> &HashMap<K, V> {
        &self.0
    }
}

impl<K: Hash + Eq + Clone, V: Clone> Deref for NonEmptyMap<K, V> {
    type Target = HashMap<K, V>;

    fn deref(&self) -> &HashMap<K, V> {
        &self.0
    }
}
