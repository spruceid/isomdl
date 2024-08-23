use ciborium::Value;
use coset::AsCborValue;
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

impl<K: Ord + Eq + Clone, V: Clone> FromIterator<(K, V)> for NonEmptyMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        NonEmptyMap::maybe_new(iter.into_iter().collect()).unwrap()
    }
}

impl<K: Ord + Eq + Clone + AsCborValue, V: Clone + AsCborValue> coset::CborSerializable
    for NonEmptyMap<K, V>
{
}
impl<K: Ord + Eq + Clone + AsCborValue, V: Clone + AsCborValue> AsCborValue for NonEmptyMap<K, V> {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let v = match value {
            Value::Map(v) => v,
            _ => {
                return Err(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "not a map".to_string()),
                ))
            }
        };
        NonEmptyMap::try_from(
            v.into_iter()
                .map(|(k, v)| Ok((K::from_cbor_value(k)?, V::from_cbor_value(v)?)))
                .collect::<coset::Result<BTreeMap<K, V>>>()?,
        )
        .map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "empty map in NonEmptyMap".to_string(),
            ))
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(
            self.into_inner()
                .into_iter()
                .map(|(k, v)| Ok((K::to_cbor_value(k)?, V::to_cbor_value(v)?)))
                .collect::<coset::Result<Vec<(Value, ciborium::Value)>>>()?,
        ))
    }
}
