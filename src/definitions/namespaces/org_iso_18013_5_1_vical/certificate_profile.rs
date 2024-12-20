use std::str::FromStr;
use isomdl_macros::FromJson;
use crate::definitions::helpers::NonEmptyVec;
use crate::definitions::namespaces::latin1::Latin1;
use crate::definitions::traits::ToCbor;

#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct CertificateProfiles(NonEmptyVec<Latin1>);

impl CertificateProfiles {
    pub fn new(profiles: Vec<String>) -> Self {
        let v: Vec<Latin1> = profiles.iter().map(|s| Latin1::from_str(s.as_str()).unwrap()).collect();
        Self(NonEmptyVec::try_from(v).unwrap())
    }
}
impl From<CertificateProfiles> for ciborium::Value {
    fn from(value: CertificateProfiles) -> ciborium::Value {
        ciborium::Value::Array(value.0.into_inner().into_iter().map(|v| v.to_cbor()).collect())
    }

}