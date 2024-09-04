use std::collections::BTreeMap;
use std::str::FromStr;

use isomdl_macros::FieldsNames;
use strum_macros::{AsRefStr, EnumString, VariantNames};
use thiserror::Error;

use crate::cbor::CborValue;
use crate::{
    definitions::{
        helpers::NonEmptyVec,
        traits::{FromJsonError, ToCbor},
    },
    macros::{FromJson, ToCbor},
};

use super::FullDate;

#[derive(Debug, Error)]
pub enum Error {
    #[error("decode error: {0}")]
    Decode(&'static str),
}

/// `driving_privileges` in the org.iso.18013.5.1 namespace.
#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct DrivingPrivileges(Vec<DrivingPrivilege>);

impl From<DrivingPrivileges> for CborValue {
    fn from(d: DrivingPrivileges) -> CborValue {
        CborValue::Array(d.0.into_iter().map(ToCbor::to_cbor).collect())
    }
}

/// The specifications of vehicle categories and restrictions
#[derive(Clone, Eq, PartialEq, EnumString, Debug, VariantNames, AsRefStr)]
pub enum VehicleCategoryCode {
    /// Motorcycles
    A,
    /// Light vehicles
    B,
    /// Goods vehicles
    C,
    /// Passenger vehicles
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
    /// Medium-sized goods vehicles
    C1,
    /// Medium-sized passenger vehicles (e.g.minibuses)
    D1,
    /// Medium-sized goods vehicles with trailers
    C1E,
    /// Medium-sized passenger vehicles (e.g., minibuses) with trailers
    D1E,
}

impl From<VehicleCategoryCode> for CborValue {
    fn from(c: VehicleCategoryCode) -> CborValue {
        CborValue::Text(c.as_ref().to_string())
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

#[derive(Clone, Debug, FromJson, FieldsNames)]
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

impl From<Codes> for CborValue {
    fn from(c: Codes) -> CborValue {
        CborValue::Array(c.0.into_inner().into_iter().map(ToCbor::to_cbor).collect())
    }
}

#[derive(Clone, Debug, FromJson, ToCbor, FieldsNames)]
#[isomdl(crate = "crate")]
pub struct Code {
    pub code: String,
    pub sign: Option<String>,
    pub value: Option<String>,
}

impl TryFrom<CborValue> for Code {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        let mut map = value
            .into_map()
            .map_err(|_| Error::Decode("Code is not a map"))?;
        Ok(Code {
            code: map
                .remove(&Code::fn_code().into())
                .ok_or(Error::Decode("code is missing"))?
                .into_text()
                .map_err(|_| Error::Decode("code is not a string"))?,
            sign: map
                .remove(&Code::fn_sign().into())
                .map(|v| {
                    v.into_text()
                        .map_err(|_| Error::Decode("sign is not a string"))
                })
                .transpose()?,
            value: map
                .remove(&Code::fn_value().into())
                .map(|v| {
                    v.into_text()
                        .map_err(|_| Error::Decode("value is not a string"))
                })
                .transpose()?,
        })
    }
}

impl From<FullDate> for CborValue {
    fn from(d: FullDate) -> CborValue {
        CborValue::Text(d.to_string())
    }
}

impl TryFrom<CborValue> for FullDate {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        let s = value
            .into_text()
            .map_err(|_| Error::Decode("FullDate is not a text"))?;
        FullDate::from_str(&s).map_err(|_| Error::Decode("FullDate is not a valid date"))
    }
}

impl From<DrivingPrivilege> for CborValue {
    fn from(d: DrivingPrivilege) -> CborValue {
        let mut map = BTreeMap::new();
        map.insert(
            DrivingPrivilege::fn_vehicle_category_code().into(),
            d.vehicle_category_code.into(),
        );
        if let Some(issue_date) = d.issue_date {
            map.insert(DrivingPrivilege::fn_issue_date().into(), issue_date.into());
        }
        if let Some(expiry_date) = d.expiry_date {
            map.insert(
                DrivingPrivilege::fn_expiry_date().into(),
                expiry_date.into(),
            );
        }
        if let Some(codes) = d.codes {
            map.insert(DrivingPrivilege::fn_expiry_date().into(), codes.to_cbor());
        }
        CborValue::Map(map)
    }
}

impl TryFrom<CborValue> for DrivingPrivilege {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        let mut map = value
            .into_map()
            .map_err(|_| Error::Decode("DrivingPrivilege is not a map"))?;

        let vehicle_category_code = VehicleCategoryCode::from_str(
            map.remove(&DrivingPrivilege::fn_vehicle_category_code().into())
                .ok_or(Error::Decode("vehicle_category_code is missing"))?
                .into_text()
                .map_err(|_| Error::Decode("vehicle_category_code is not a string"))?
                .as_str(),
        )
        .map_err(|_| Error::Decode("vehicle_category_code is not a valid VehicleCategoryCode"))?;

        let issue_date: Option<FullDate> = map
            .remove(&DrivingPrivilege::fn_issue_date().into())
            .map(|v| {
                v.try_into()
                    .map_err(|_| Error::Decode("issue_date is not a FullDate"))
            })
            .transpose()?;
        let expiry_date: Option<FullDate> = map
            .remove(&DrivingPrivilege::fn_expiry_date().into())
            .map(|v| {
                v.try_into()
                    .map_err(|_| Error::Decode("expiry_date is not a FullDate"))
            })
            .transpose()?;
        let codes: Option<Codes> = map
            .remove(&DrivingPrivilege::fn_codes().into())
            .map(|v| {
                v.try_into()
                    .map_err(|_| Error::Decode("codes is not a Codes"))
            })
            .transpose()?;
        Ok(DrivingPrivilege {
            vehicle_category_code,
            issue_date,
            expiry_date,
            codes,
        })
    }
}

impl TryFrom<CborValue> for Codes {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        let v = value
            .into_array()
            .map_err(|_| Error::Decode("Codes is not an array"))?;
        Ok(Codes(
            v.into_iter()
                .map(|v| Code::try_from(v).map_err(|_| Error::Decode("Code is not a Code")))
                .collect::<Result<NonEmptyVec<Code>, Error>>()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::cbor::CborValue;
    use crate::definitions::traits::{FromJson, ToCbor};

    use super::VehicleCategoryCode;

    #[test]
    fn vehicle_category_code() {
        let c = VehicleCategoryCode::A.as_ref().to_string();
        let c: VehicleCategoryCode = c.parse().unwrap();
        assert_eq!(c, VehicleCategoryCode::A);

        let v = c.to_cbor();
        assert_eq!(v, CborValue::Text("A".to_string()));

        let j = serde_json::json!("A");
        let c = VehicleCategoryCode::from_json(&j).unwrap();
        assert_eq!(c, VehicleCategoryCode::A);
    }
}
