use std::collections::BTreeMap;

use isomdl_macros::{FieldsNames, ToCbor};

use crate::cbor::CborValue;
use crate::{
    definitions::{helpers::NonEmptyVec, traits::ToCbor},
    macros::FromJson,
};

use super::FullDate;

/// `domestic_driving_privileges` in the org.iso.18013.5.1.aamva namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.0).
#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct DomesticDrivingPrivileges(Vec<DomesticDrivingPrivilege>);

impl ToCbor for DomesticDrivingPrivileges {
    fn to_cbor(self) -> CborValue {
        CborValue::Array(self.0.into_iter().map(ToCbor::to_cbor).collect())
    }
}

#[derive(Clone, Debug, FromJson, FieldsNames)]
#[isomdl(crate = "crate")]
pub struct DomesticDrivingPrivilege {
    pub domestic_vehicle_class: Option<DomesticVehicleClass>,
    pub domestic_vehicle_restrictions: Option<DomesticVehicleRestrictions>,
    pub domestic_vehicle_endorsements: Option<DomesticVehicleEndorsements>,
}

impl ToCbor for DomesticDrivingPrivilege {
    fn to_cbor(self) -> CborValue {
        let mut map = BTreeMap::new();
        if let Some(domestic_vehicle_class) = self.domestic_vehicle_class {
            map.insert(
                DomesticDrivingPrivilege::fn_domestic_vehicle_class().into(),
                domestic_vehicle_class.to_cbor(),
            );
        }
        if let Some(domestic_vehicle_restrictions) = self.domestic_vehicle_restrictions {
            map.insert(
                DomesticDrivingPrivilege::fn_domestic_vehicle_restrictions().into(),
                domestic_vehicle_restrictions.to_cbor(),
            );
        }
        if let Some(domestic_vehicle_endorsements) = self.domestic_vehicle_endorsements {
            map.insert(
                DomesticDrivingPrivilege::fn_domestic_vehicle_endorsements().into(),
                domestic_vehicle_endorsements.to_cbor(),
            );
        }
        CborValue::Map(map)
    }
}

#[derive(Clone, Debug, FromJson, FieldsNames)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleClass {
    pub domestic_vehicle_class_code: String,
    pub domestic_vehicle_class_description: String,
    pub issue_date: Option<FullDate>,
    pub expiry_date: Option<FullDate>,
}

impl ToCbor for DomesticVehicleClass {
    fn to_cbor(self) -> CborValue {
        let mut map = BTreeMap::new();
        map.insert(
            DomesticVehicleClass::fn_domestic_vehicle_class_code().into(),
            self.domestic_vehicle_class_code.into(),
        );
        map.insert(
            DomesticVehicleClass::fn_domestic_vehicle_class_description().into(),
            self.domestic_vehicle_class_description.into(),
        );
        if let Some(issue_date) = self.issue_date {
            map.insert(
                DomesticVehicleClass::fn_issue_date().into(),
                issue_date.into(),
            );
        }
        if let Some(expiry_date) = self.expiry_date {
            map.insert(
                DomesticVehicleClass::fn_expiry_date().into(),
                expiry_date.into(),
            );
        }
        CborValue::Map(map)
    }
}

#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleRestrictions(NonEmptyVec<DomesticVehicleRestriction>);

impl ToCbor for DomesticVehicleRestrictions {
    fn to_cbor(self) -> CborValue {
        CborValue::Array(
            self.0
                .into_inner()
                .into_iter()
                .map(ToCbor::to_cbor)
                .collect(),
        )
    }
}

// todo: use ToCbor
// #[derive(Clone, Debug, FromJson, ToCbor)]
#[derive(Clone, Debug, FieldsNames, FromJson)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleRestriction {
    pub domestic_vehicle_restriction_code: Option<String>,
    pub domestic_vehicle_restriction_description: String,
}

impl ToCbor for DomesticVehicleRestriction {
    fn to_cbor(self) -> CborValue {
        let mut map = BTreeMap::new();
        if let Some(domestic_vehicle_restriction_code) = self.domestic_vehicle_restriction_code {
            map.insert(
                DomesticVehicleRestriction::fn_domestic_vehicle_restriction_code().into(),
                domestic_vehicle_restriction_code.into(),
            );
        }
        map.insert(
            DomesticVehicleRestriction::fn_domestic_vehicle_restriction_description().into(),
            self.domestic_vehicle_restriction_description.into(),
        );
        CborValue::Map(map)
    }
}

#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleEndorsements(NonEmptyVec<DomesticVehicleEndorsement>);

impl ToCbor for DomesticVehicleEndorsements {
    fn to_cbor(self) -> CborValue {
        CborValue::Array(
            self.0
                .into_inner()
                .into_iter()
                .map(ToCbor::to_cbor)
                .collect(),
        )
    }
}

#[derive(Clone, Debug, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct DomesticVehicleEndorsement {
    pub domestic_vehicle_endorsement_code: Option<String>,
    pub domestic_vehicle_endorsement_description: String,
}
