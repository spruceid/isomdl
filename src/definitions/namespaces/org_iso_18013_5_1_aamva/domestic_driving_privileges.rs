use super::FullDate;
use crate::definitions::helpers::NonEmptyVec;
use serde_cbor::Value as Cbor;
use std::{collections::BTreeMap};

pub type DomesticDrivingPrivileges = Vec<DomesticDrivingPrivilege>;

#[derive(Clone, Debug, FromJson)]
pub struct DomesticDrivingPrivilege {
    pub domestic_vehicle_class: Option<DomesticVehicleClass>,
    pub domestic_vehicle_restrictions: Option<NonEmptyVec<DomesticVehicleRestriction>>,
    pub domestic_vehicle_endorsements: Option<NonEmptyVec<DomesticVehicleEndorsement>>,
}

#[derive(Clone, Debug, FromJson)]
pub struct DomesticVehicleClass {
    pub domestic_vehicle_class_code: String,
    pub domestic_vehicle_class_description: String,
    pub issue_date: Option<FullDate>,
    pub expiry_date: Option<FullDate>,
}

#[derive(Clone, Debug, FromJson)]
pub struct DomesticVehicleRestriction {
    pub domestic_vehicle_restriction_code: Option<String>,
    pub domestic_vehicle_restriction_description: String,
}

#[derive(Clone, Debug, FromJson)]
pub struct DomesticVehicleEndorsement {
    pub domestic_vehicle_endorsement_code: Option<String>,
    pub domestic_vehicle_endorsement_description: String,
}

impl From<DomesticDrivingPrivilege> for Cbor {
    fn from(d: DomesticDrivingPrivilege) -> Cbor {
        let mut map = BTreeMap::new();
        if let Some(domestic_vehicle_class) = d.domestic_vehicle_class {
            map.insert(
                "domestic_vehicle_class".to_string().into(),
                domestic_vehicle_class.into(),
            );
        }
        if let Some(domestic_vehicle_restrictions) = d.domestic_vehicle_restrictions {
            map.insert(
                "domestic_vehicle_restrictions".to_string().into(),
                domestic_vehicle_restrictions
                    .into_inner()
                    .into_iter()
                    .map(Cbor::from)
                    .collect::<Vec<Cbor>>()
                    .into(),
            );
        }
        if let Some(domestic_vehicle_endorsements) = d.domestic_vehicle_endorsements {
            map.insert(
                "domestic_vehicle_endorsements".to_string().into(),
                domestic_vehicle_endorsements
                    .into_inner()
                    .into_iter()
                    .map(Cbor::from)
                    .collect::<Vec<Cbor>>()
                    .into(),
            );
        }
        Cbor::Map(map)
    }
}

impl From<DomesticVehicleClass> for Cbor {
    fn from(d: DomesticVehicleClass) -> Cbor {
        let mut map = BTreeMap::new();
        map.insert(
            "domestic_vehicle_class_code".to_string().into(),
            d.domestic_vehicle_class_code.into(),
        );
        map.insert(
            "domestic_vehicle_class_description".to_string().into(),
            d.domestic_vehicle_class_description.into(),
        );
        if let Some(issue_date) = d.issue_date {
            map.insert("issue_date".to_string().into(), issue_date.into());
        }
        if let Some(expiry_date) = d.expiry_date {
            map.insert("expiry_date".to_string().into(), expiry_date.into());
        }
        Cbor::Map(map)
    }
}

impl From<DomesticVehicleRestriction> for Cbor {
    fn from(d: DomesticVehicleRestriction) -> Cbor {
        let mut map = BTreeMap::new();
        if let Some(domestic_vehicle_restriction_code) = d.domestic_vehicle_restriction_code {
            map.insert(
                "domestic_vehicle_restriction_code".to_string().into(),
                domestic_vehicle_restriction_code.into(),
            );
        }
        map.insert(
            "domestic_vehicle_restriction_description"
                .to_string()
                .into(),
            d.domestic_vehicle_restriction_description.into(),
        );
        Cbor::Map(map)
    }
}

impl From<DomesticVehicleEndorsement> for Cbor {
    fn from(d: DomesticVehicleEndorsement) -> Cbor {
        let mut map = BTreeMap::new();
        if let Some(domestic_vehicle_endorsement_code) = d.domestic_vehicle_endorsement_code {
            map.insert(
                "domestic_vehicle_endorsement_code".to_string().into(),
                domestic_vehicle_endorsement_code.into(),
            );
        }
        map.insert(
            "domestic_vehicle_endorsement_description"
                .to_string()
                .into(),
            d.domestic_vehicle_endorsement_description.into(),
        );
        Cbor::Map(map)
    }
}
