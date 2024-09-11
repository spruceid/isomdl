use coset::AsCborValue;
use serde::{Deserialize, Serialize};

/// This is a small helper wrapper to deal with `coset` types that don't
/// implement `Serialize`/`Deserialize` but only `AsCborValue`.
pub struct SerializedAsCborValue<T>(pub T);

impl<'a, T: Clone + AsCborValue> Serialize for SerializedAsCborValue<&'a T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0
            .clone()
            .to_cbor_value()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de, T: AsCborValue> Deserialize<'de> for SerializedAsCborValue<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::from_cbor_value(ciborium::Value::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
            .map(Self)
    }
}
