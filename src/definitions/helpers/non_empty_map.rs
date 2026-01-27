use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ops::Deref};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(try_from = "BTreeMap<K, V>", into = "BTreeMap<K, V>")]
pub struct NonEmptyMap<K: Ord + Eq + Clone, V: Clone>(BTreeMap<K, V>);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot construct a non-empty vec from an empty vec")]
    Empty,
}

impl<K: Ord + Eq + Clone, V: Clone> NonEmptyMap<K, V> {
    pub fn new(k: K, v: V) -> Self {
        let mut inner = BTreeMap::new();
        inner.insert(k, v);
        Self(inner)
    }

    pub fn maybe_new(m: BTreeMap<K, V>) -> Option<Self> {
        Self::try_from(m).ok()
    }

    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.0.insert(k, v)
    }

    pub fn into_inner(self) -> BTreeMap<K, V> {
        self.0
    }

    pub fn iter_mut(&mut self) -> std::collections::btree_map::IterMut<'_, K, V> {
        self.0.iter_mut()
    }
}

impl<K: Ord + Eq + Clone, V: Clone> TryFrom<BTreeMap<K, V>> for NonEmptyMap<K, V> {
    type Error = Error;

    fn try_from(m: BTreeMap<K, V>) -> Result<NonEmptyMap<K, V>, Error> {
        if m.is_empty() {
            return Err(Error::Empty);
        }
        Ok(NonEmptyMap(m))
    }
}

impl<K: Ord + Eq + Clone, V: Clone> From<NonEmptyMap<K, V>> for BTreeMap<K, V> {
    fn from(NonEmptyMap(m): NonEmptyMap<K, V>) -> BTreeMap<K, V> {
        m
    }
}

impl<K: Ord + Eq + Clone, V: Clone> AsRef<BTreeMap<K, V>> for NonEmptyMap<K, V> {
    fn as_ref(&self) -> &BTreeMap<K, V> {
        &self.0
    }
}

impl<K: Ord + Eq + Clone, V: Clone> Deref for NonEmptyMap<K, V> {
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &BTreeMap<K, V> {
        &self.0
    }
}
