use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

pub struct BTreeMapCbor<V>(pub BTreeMap<String, V>)
where
    V: Clone + AsCborValue;

impl<V> Deref for BTreeMapCbor<V>
where
    V: Clone + AsCborValue,
{
    type Target = BTreeMap<String, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V> DerefMut for BTreeMapCbor<V>
where
    V: Clone + AsCborValue,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<V> CborSerializable for BTreeMapCbor<V> where V: Clone + AsCborValue {}
impl<V> AsCborValue for BTreeMapCbor<V>
where
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
                        Ok::<(String, V), coset::CoseError>((
                            k.into_text().map_err(|_| {
                                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                    None,
                                    "not a map".to_string(),
                                ))
                            })?,
                            V::from_cbor_value(v)?,
                        ))
                    })
                    .collect::<coset::Result<BTreeMap<String, V>>>()
            })
            .map(BTreeMapCbor)
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(
            self.0
                .into_iter()
                .flat_map(|(k, v)| {
                    Ok::<(Value, Value), coset::CoseError>((Value::Text(k), v.to_cbor_value()?))
                })
                .collect(),
        ))
    }
}
