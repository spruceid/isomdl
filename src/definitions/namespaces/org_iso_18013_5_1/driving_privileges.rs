use super::FullDate;
use crate::{
    definitions::{helpers::NonEmptyVec, traits::ToCbor},
    macros::{FromJson, ToCbor},
};
use serde_cbor::Value as Cbor;

/// `driving_privileges` in the org.iso.18013.5.1 namespace.
#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct DrivingPrivileges(Vec<DrivingPrivilege>);

impl From<DrivingPrivileges> for Cbor {
    fn from(d: DrivingPrivileges) -> Cbor {
        Cbor::Array(d.0.into_iter().map(ToCbor::to_cbor).collect())
    }
}

#[derive(Clone, Debug, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct DrivingPrivilege {
    pub vehicle_category_code: String,
    pub issue_date: Option<FullDate>,
    pub expiry_date: Option<FullDate>,
    pub codes: Option<Codes>,
}

#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct Codes(NonEmptyVec<Code>);

impl From<Codes> for Cbor {
    fn from(c: Codes) -> Cbor {
        Cbor::Array(c.0.into_inner().into_iter().map(ToCbor::to_cbor).collect())
    }
}

#[derive(Clone, Debug, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct Code {
    pub code: String,
    pub sign: Option<String>,
    pub value: Option<String>,
}
