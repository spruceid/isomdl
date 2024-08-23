use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

use crate::definitions::helpers::NonEmptyMap;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot construct a non-empty vec from an empty vec")]
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct BTreeMapCbor<K, V>(BTreeMap<K, V>)
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue;

impl<K, V> Default for BTreeMapCbor<K, V>
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue,
{
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<K, V> BTreeMapCbor<K, V>
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue,
{
    pub fn new() -> Self {
        Self(BTreeMap::<K, V>::new())
    }
}

impl<K, V> Deref for BTreeMapCbor<K, V>
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue,
{
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for BTreeMapCbor<K, V>
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> CborSerializable for BTreeMapCbor<K, V>
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue,
{
}
impl<K, V> AsCborValue for BTreeMapCbor<K, V>
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue,
{
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "not a map".to_string(),
                ))
            })
            .and_then(|v| {
                v.into_iter()
                    .map(|(k, v)| {
                        Ok::<(K, V), coset::CoseError>((
                            K::try_from(k).map_err(|_| {
                                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                    None,
                                    "invalid key".to_string(),
                                ))
                            })?,
                            V::from_cbor_value(v)?,
                        ))
                    })
                    .collect::<coset::Result<BTreeMap<K, V>>>()
            })
            .map(BTreeMapCbor)
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(
            self.0
                .into_iter()
                .flat_map(|(k, v)| {
                    Ok::<(Value, Value), coset::CoseError>((k.into(), v.to_cbor_value()?))
                })
                .collect(),
        ))
    }
}

impl<K, V> Serialize for BTreeMapCbor<K, V>
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue,
{
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        unimplemented!()
    }
}

impl<'de, K, V> Deserialize<'de> for BTreeMapCbor<K, V>
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue,
{
    fn deserialize<D>(_d: D) -> Result<BTreeMapCbor<K, V>, D::Error>
    where
        D: Deserializer<'de>,
    {
        unimplemented!()
    }
}

impl<K, V> FromIterator<(K, V)> for BTreeMapCbor<K, V>
where
    K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>,
    V: Clone + AsCborValue,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        BTreeMapCbor(iter.into_iter().collect())
    }
}

impl<K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>, V: Clone + AsCborValue>
    TryFrom<BTreeMap<K, V>> for BTreeMapCbor<K, V>
{
    type Error = Error;

    fn try_from(m: BTreeMap<K, V>) -> Result<BTreeMapCbor<K, V>, Error> {
        if m.is_empty() {
            return Err(Error::Empty);
        }
        Ok(BTreeMapCbor(m))
    }
}

impl<K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>, V: Clone + AsCborValue>
    From<BTreeMapCbor<K, V>> for BTreeMap<K, V>
{
    fn from(BTreeMapCbor(m): BTreeMapCbor<K, V>) -> BTreeMap<K, V> {
        m
    }
}

impl<K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>, V: Clone + AsCborValue>
    AsRef<BTreeMap<K, V>> for BTreeMapCbor<K, V>
{
    fn as_ref(&self) -> &BTreeMap<K, V> {
        &self.0
    }
}

impl<K: Ord + Eq + Clone + Into<Value> + TryFrom<Value>, V: Clone + AsCborValue>
    From<BTreeMapCbor<K, V>> for NonEmptyMap<K, V>
{
    fn from(BTreeMapCbor(m): BTreeMapCbor<K, V>) -> NonEmptyMap<K, V> {
        m.into_iter().collect::<NonEmptyMap<K, V>>()
    }
}
