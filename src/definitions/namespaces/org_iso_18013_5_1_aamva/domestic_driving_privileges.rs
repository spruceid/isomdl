use super::FullDate;
use crate::{
    definitions::{helpers::NonEmptyVec, traits::ToCbor},
    macros::{FromJson, ToCbor},
};
use crate::cbor::Value as Cbor;

/// `domestic_driving_privileges` in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct DomesticDrivingPrivileges(Vec<DomesticDrivingPrivilege>);

impl ToCbor for DomesticDrivingPrivileges {
    fn to_cbor(self) -> Cbor {
        ciborium::Value::Array(self.0.into_iter().map(|v| v.to_cbor().into()).collect()).into()
    }
}

#[derive(Clone, Debug, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct DomesticDrivingPrivilege {
    pub domestic_vehicle_class: Option<DomesticVehicleClass>,
    pub domestic_vehicle_restrictions: Option<DomesticVehicleRestrictions>,
    pub domestic_vehicle_endorsements: Option<DomesticVehicleEndorsements>,
}

#[derive(Clone, Debug, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleClass {
    pub domestic_vehicle_class_code: String,
    pub domestic_vehicle_class_description: String,
    pub issue_date: Option<FullDate>,
    pub expiry_date: Option<FullDate>,
}

#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleRestrictions(NonEmptyVec<DomesticVehicleRestriction>);

impl ToCbor for DomesticVehicleRestrictions {
    fn to_cbor(self) -> Cbor {
        ciborium::Value::Array(
            self.0
                .into_inner()
                .into_iter()
                .map(|v| v.to_cbor().into())
                .collect(),
        ).into()
    }
}

#[derive(Clone, Debug, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleRestriction {
    pub domestic_vehicle_restriction_code: Option<String>,
    pub domestic_vehicle_restriction_description: String,
}

#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleEndorsements(NonEmptyVec<DomesticVehicleEndorsement>);

impl ToCbor for DomesticVehicleEndorsements {
    fn to_cbor(self) -> Cbor {
        ciborium::Value::Array(
            self.0
                .into_inner()
                .into_iter()
                .map(|v| v.to_cbor().into())
                .collect(),
        ).into()
    }
}

#[derive(Clone, Debug, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleEndorsement {
    pub domestic_vehicle_endorsement_code: Option<String>,
    pub domestic_vehicle_endorsement_description: String,
}
