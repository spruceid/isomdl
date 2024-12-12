use isomdl_macros::FromJson;
use crate::definitions::helpers::NonEmptyVec;
use crate::definitions::namespaces::latin1::Latin1;
use crate::definitions::traits::ToCbor;

#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct CertificateProfiles(NonEmptyVec<Latin1>);

impl From<CertificateProfiles> for ciborium::Value {
    fn from(value: CertificateProfiles) -> ciborium::Value {
        ciborium::Value::Array(value.0.into_inner().into_iter().map(|v| v.to_cbor()).collect())
    }

}