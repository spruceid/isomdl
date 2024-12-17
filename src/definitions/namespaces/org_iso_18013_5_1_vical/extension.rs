use std::collections::BTreeMap;
use isomdl_macros::FromJson;
use crate::definitions::helpers::ByteStr;
use crate::definitions::traits::ToCbor;

#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct Extensions(BTreeMap<String, ByteStr>);

impl Extensions {
    pub fn new(extensions: BTreeMap<String, Vec<u8>>) -> Self {
        let v = extensions.iter().map( | (k, v)| (k.clone(), ByteStr::from(v.clone()))).collect();
        Self(v)
    }
}
impl From<Extensions> for ciborium::Value {
    fn from(extensions: Extensions) -> ciborium::Value {
        ciborium::Value::Map(extensions.0.into_iter().map(|(k, v)| (k.to_cbor(), v.to_cbor())).collect())
    }
}