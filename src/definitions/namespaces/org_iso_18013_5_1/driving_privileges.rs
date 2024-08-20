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
#[isomdl(crate = "crate")]
pub struct DrivingPrivileges(Vec<DrivingPrivilege>);

impl From<DrivingPrivileges> for Cbor {
    fn from(d: DrivingPrivileges) -> Cbor {
        Cbor::Array(d.0.into_iter().map(ToCbor::to_cbor).collect())
    }
}

/// The specifications of vehicle categories and restrictions
#[derive(Clone, Eq, PartialEq, EnumString, Debug, EnumVariantNames, AsRefStr)]
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
        String::from_json(v)?
            .to_uppercase()
            .parse::<VehicleCategoryCode>()
            .map_err(|err| FromJsonError::Parsing(anyhow::Error::new(err)))
    }
}

#[derive(Clone, Debug, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct DrivingPrivilege {
    pub vehicle_category_code: VehicleCategoryCode,
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

#[cfg(test)]
mod tests {
    use crate::definitions::traits::{FromJson, ToCbor};

    use super::VehicleCategoryCode;

    #[test]
    fn vehicle_category_code() {
        let c = VehicleCategoryCode::A.as_ref().to_string();
        let c: VehicleCategoryCode = c.parse().unwrap();
        assert_eq!(c, VehicleCategoryCode::A);

        let v = c.to_cbor();
        assert_eq!(v, serde_cbor::Value::Text("A".to_string()));

        let j = serde_json::json!("A");
        let c = VehicleCategoryCode::from_json(&j).unwrap();
        assert_eq!(c, VehicleCategoryCode::A);
    }
}
