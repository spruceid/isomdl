use std::collections::BTreeMap;
use crate::definitions::{
    helpers::ByteStr,
    traits::{FromMap, FromJson, FromJsonError},
};
use serde_json::{Map, Value};

// TODO: Obtain a licence for ISO/IEC 19785-3:2020, as Table 7 in that standard contains the list
// of all biometric templates.

#[derive(Debug, Clone)]
pub struct BiometricTemplate(BTreeMap<String, ByteStr>);

impl FromMap for BiometricTemplate {
    fn from_map(m: &Map<String, Value>) -> Result<Self, FromJsonError>{
        m.iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("biometric_template_")
                    .map(|k| Ok((k.to_string(), ByteStr::from_json(v)?)))
            })
            .collect::<Result<_,_>>()
            .map(Self)
    }
}
