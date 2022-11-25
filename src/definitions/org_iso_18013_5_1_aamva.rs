use crate::definitions::{fulldate::FullDate, helpers::NonEmptyVec};
use serde::Deserialize;
use serde_cbor::Value;
use std::{collections::BTreeMap, str::FromStr};

pub type DomesticDrivingPrivileges = Vec<DomesticDrivingPrivilege>;

#[derive(Clone, Debug)]
pub struct DomesticDrivingPrivilege {
    pub domestic_vehicle_class: Option<DomesticVehicleClass>,
    pub domestic_vehicle_restrictions: Option<NonEmptyVec<DomesticVehicleRestriction>>,
    pub domestic_vehicle_endorsements: Option<NonEmptyVec<DomesticVehicleEndorsement>>,
}

#[derive(Clone, Debug)]
pub struct DomesticVehicleClass {
    pub domestic_vehicle_class_code: String,
    pub domestic_vehicle_class_description: String,
    pub issue_date: Option<FullDate>,
    pub expiry_date: Option<FullDate>,
}

#[derive(Clone, Debug)]
pub struct DomesticVehicleRestriction {
    pub domestic_vehicle_restriction_code: Option<String>,
    pub domestic_vehicle_restriction_description: String,
}

#[derive(Clone, Debug)]
pub struct DomesticVehicleEndorsement {
    pub domestic_vehicle_endorsement_code: Option<String>,
    pub domestic_vehicle_endorsement_description: String,
}

// Private intermediary types when deserializing from json.
// TODO: This is needed to prevent the need of implementing serde traits on the public types, as we
// want to prevent serde_cbor from being used, and instead use the `From` implementation to convert
// into serde_cbor::Value. We should consider defining a trait instead (i.e. `trait FromJson`),
// that can be used across all isomdl and aamva data element types to convert from json.

#[derive(Clone, Debug, Deserialize)]
struct DomesticDrivingPrivilegePriv {
    pub domestic_vehicle_class: Option<DomesticVehicleClassPriv>,
    pub domestic_vehicle_restrictions: Option<NonEmptyVec<DomesticVehicleRestrictionPriv>>,
    pub domestic_vehicle_endorsements: Option<NonEmptyVec<DomesticVehicleEndorsementPriv>>,
}

#[derive(Clone, Debug, Deserialize)]
struct DomesticVehicleClassPriv {
    pub domestic_vehicle_class_code: String,
    pub domestic_vehicle_class_description: String,
    pub issue_date: Option<String>,
    pub expiry_date: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct DomesticVehicleRestrictionPriv {
    pub domestic_vehicle_restriction_code: Option<String>,
    pub domestic_vehicle_restriction_description: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DomesticVehicleEndorsementPriv {
    pub domestic_vehicle_endorsement_code: Option<String>,
    pub domestic_vehicle_endorsement_description: String,
}

impl From<DomesticDrivingPrivilege> for Value {
    fn from(d: DomesticDrivingPrivilege) -> Value {
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
                    .map(Value::from)
                    .collect::<Vec<Value>>()
                    .into(),
            );
        }
        if let Some(domestic_vehicle_endorsements) = d.domestic_vehicle_endorsements {
            map.insert(
                "domestic_vehicle_endorsements".to_string().into(),
                domestic_vehicle_endorsements
                    .into_inner()
                    .into_iter()
                    .map(Value::from)
                    .collect::<Vec<Value>>()
                    .into(),
            );
        }
        Value::Map(map)
    }
}

impl From<DomesticVehicleClass> for Value {
    fn from(d: DomesticVehicleClass) -> Value {
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
        Value::Map(map)
    }
}

impl From<DomesticVehicleRestriction> for Value {
    fn from(d: DomesticVehicleRestriction) -> Value {
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
        Value::Map(map)
    }
}

impl From<DomesticVehicleEndorsement> for Value {
    fn from(d: DomesticVehicleEndorsement) -> Value {
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
        Value::Map(map)
    }
}

pub fn privileges_from_json(j: serde_json::Value) -> anyhow::Result<DomesticDrivingPrivileges> {
    let privileges: Vec<DomesticDrivingPrivilegePriv> = serde_json::from_value(j)?;
    privileges
        .into_iter()
        .map(DomesticDrivingPrivilege::try_from)
        .collect()
}

impl TryFrom<DomesticDrivingPrivilegePriv> for DomesticDrivingPrivilege {
    type Error = anyhow::Error;

    fn try_from(d: DomesticDrivingPrivilegePriv) -> Result<Self, Self::Error> {
        Ok(Self {
            domestic_vehicle_class: d
                .domestic_vehicle_class
                .map(TryInto::try_into)
                .transpose()?,
            domestic_vehicle_restrictions: d.domestic_vehicle_restrictions.map(NonEmptyVec::into),
            domestic_vehicle_endorsements: d.domestic_vehicle_endorsements.map(NonEmptyVec::into),
        })
    }
}

impl TryFrom<DomesticVehicleClassPriv> for DomesticVehicleClass {
    type Error = anyhow::Error;

    fn try_from(d: DomesticVehicleClassPriv) -> Result<Self, Self::Error> {
        Ok(DomesticVehicleClass {
            domestic_vehicle_class_code: d.domestic_vehicle_class_code,
            domestic_vehicle_class_description: d.domestic_vehicle_class_description,
            issue_date: d.issue_date.map(|s| FullDate::from_str(&s)).transpose()?,
            expiry_date: d.expiry_date.map(|s| FullDate::from_str(&s)).transpose()?,
        })
    }
}

impl From<DomesticVehicleRestrictionPriv> for DomesticVehicleRestriction {
    fn from(d: DomesticVehicleRestrictionPriv) -> Self {
        DomesticVehicleRestriction {
            domestic_vehicle_restriction_code: d.domestic_vehicle_restriction_code,
            domestic_vehicle_restriction_description: d.domestic_vehicle_restriction_description,
        }
    }
}

impl From<DomesticVehicleEndorsementPriv> for DomesticVehicleEndorsement {
    fn from(d: DomesticVehicleEndorsementPriv) -> Self {
        DomesticVehicleEndorsement {
            domestic_vehicle_endorsement_code: d.domestic_vehicle_endorsement_code,
            domestic_vehicle_endorsement_description: d.domestic_vehicle_endorsement_description,
        }
    }
}
