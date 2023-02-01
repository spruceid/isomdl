use crate::definitions::{
    helpers::ByteStr,
    traits::{FromJson, FromJsonError, FromMap},
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

// TODO: Obtain a licence for ISO/IEC 19785-3:2020, as Table 7 in that standard contains the list
// of all biometric templates.

/// `biometric_template_xx` in the org.iso.18013.5.1 namespace.
#[derive(Debug, Clone)]
pub struct BiometricTemplate(BTreeMap<String, ByteStr>);

impl FromMap for BiometricTemplate {
    fn from_map(m: &Map<String, Value>) -> Result<Self, FromJsonError> {
        m.iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("biometric_template_")
                    .map(|k| Ok((k.to_string(), ByteStr::from_json(v)?)))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}
