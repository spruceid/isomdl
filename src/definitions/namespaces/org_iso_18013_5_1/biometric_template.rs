use crate::definitions::{
    helpers::ByteStr,
    traits::{FromJson, FromJsonError, FromJsonMap, ToNamespaceMap},
};
use serde_json::{Map, Value as Json};
use std::collections::BTreeMap;

/// `biometric_template_xx` in the org.iso.18013.5.1 namespace.
#[derive(Debug, Clone)]
pub struct BiometricTemplate(pub BTreeMap<String, ByteStr>);

impl FromJsonMap for BiometricTemplate {
    fn from_map(m: &Map<String, Json>) -> Result<Self, FromJsonError> {
        m.iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("biometric_template_")
                    .map(|k| Ok((k.to_string(), ByteStr::from_json(v)?)))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl ToNamespaceMap for BiometricTemplate {
    fn to_ns_map(self) -> BTreeMap<String, ciborium::Value> {
        self.0
            .into_iter()
            .map(|(k, v)| (format!("biometric_template_{k}"), v.into()))
            .collect()
    }
}
