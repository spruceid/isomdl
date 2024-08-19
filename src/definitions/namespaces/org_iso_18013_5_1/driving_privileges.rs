use super::FullDate;
use crate::{
    definitions::{
        helpers::NonEmptyVec,
        traits::{FromJsonError, ToCbor},
    },
    macros::{FromJson, ToCbor},
};
use serde_cbor::Value as Cbor;
use strum_macros::{AsRefStr, EnumString, EnumVariantNames};

/// `driving_privileges` in the org.iso.18013.5.1 namespace.
#[derive(Clone, Debug, FromJson)]
pub struct DrivingPrivileges(Vec<DrivingPrivilege>);

impl From<DrivingPrivileges> for Cbor {
    fn from(d: DrivingPrivileges) -> Cbor {
        Cbor::Array(d.0.into_iter().map(ToCbor::to_cbor).collect())
    }
}

/// The specifications of vehicle categories and restrictions
#[derive(Clone, EnumString, Debug, EnumVariantNames, AsRefStr)]
pub enum VehicleCategoryCode {
    /// Motorcycles
    A,
    /// Light vehicles
    B,
    /// Goods vehicles
    C,
    // Passenger vehicles
    D,
    /// Light vehicles with trailers
    BE,
    /// Goods vehicles with trailers
    CE,
    /// Passenger vehicles with trailers
    DE,
    ///Mopeds
    AM,
    /// Light motorcycles
    A1,
    /// Medium motorcycles
    A2,
    /// Light vehicles
    B1,
    /// Medium sized goods vehicles
    C1,
    /// Medium sized passenger vehicles (e.g.minibuses)
    D1,
    /// Medium sized goods vehicles with trailers
    C1E,
    /// Medium sized passenger vehicles (e.g. minibuses) with trailers
    D1E,
}

impl From<VehicleCategoryCode> for Cbor {
    fn from(c: VehicleCategoryCode) -> Cbor {
        Cbor::Text(c.as_ref().to_string())
    }
}

impl crate::definitions::traits::FromJson for VehicleCategoryCode {
    fn from_json(v: &serde_json::Value) -> Result<Self, FromJsonError> {
        v.as_str()
            .map(str::to_uppercase)
            .map(|s| s.parse::<VehicleCategoryCode>())
            .unwrap_or(Err(strum::ParseError::VariantNotFound))
            .map_err(|_| FromJsonError::Missing)
    }
}

#[derive(Clone, Debug, FromJson, ToCbor)]
pub struct DrivingPrivilege {
    pub vehicle_category_code: VehicleCategoryCode,
    pub issue_date: Option<FullDate>,
    pub expiry_date: Option<FullDate>,
    pub codes: Option<Codes>,
}

#[derive(Clone, Debug, FromJson)]
pub struct Codes(NonEmptyVec<Code>);

impl From<Codes> for Cbor {
    fn from(c: Codes) -> Cbor {
        Cbor::Array(c.0.into_inner().into_iter().map(ToCbor::to_cbor).collect())
    }
}

#[derive(Clone, Debug, FromJson, ToCbor)]
pub struct Code {
    pub code: String,
    pub sign: Option<String>,
    pub value: Option<String>,
}
