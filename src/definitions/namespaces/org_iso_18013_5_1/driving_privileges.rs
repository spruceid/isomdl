use std::collections::BTreeMap;
use std::str::FromStr;

use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use isomdl_macros::FieldsNames;
use thiserror::Error;

use crate::cbor::CborValue;
use crate::{
    definitions::{helpers::NonEmptyVec, traits::ToCbor},
    macros::FromJson,
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

#[derive(Clone, Debug, FieldsNames, FromJson)]
#[isomdl(crate = "crate")]
pub struct DrivingPrivilege {
    pub vehicle_category_code: String,
    pub issue_date: Option<FullDate>,
    pub expiry_date: Option<FullDate>,
    pub codes: Option<Codes>,
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

        let vehicle_category_code = map
            .remove(&DrivingPrivilege::fn_vehicle_category_code().into())
            .ok_or(Error::Decode("vehicle_category_code is missing"))?
            .try_into()
            .map_err(|_| Error::Decode("vehicle_category_code is not a string"))?;
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
                .map(|v| v.try_into())
                .collect::<Result<_, _>>()
                .map_err(|_| Error::Decode("Codes contains invalid Code"))?,
        ))
    }
}

#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct Codes(NonEmptyVec<Code>);

impl ToCbor for Codes {
    fn to_cbor(self) -> CborValue {
        CborValue::Array(
            self.0
                .into_inner()
                .into_iter()
                .map(ToCbor::to_cbor)
                .collect::<Vec<CborValue>>(),
        )
    }
}

// todo: use ToCbor
// #[derive(Clone, Debug, FromJson, ToCbor)]
#[derive(Clone, Debug, FieldsNames, FromJson)]
#[isomdl(crate = "crate")]
pub struct Code {
    pub code: String,
    pub sign: Option<String>,
    pub value: Option<String>,
}

impl From<Code> for CborValue {
    fn from(c: Code) -> CborValue {
        let mut map = BTreeMap::new();
        map.insert(Code::fn_code().into(), c.code.into());
        if let Some(sign) = c.sign {
            map.insert(Code::fn_sign().into(), sign.into());
        }
        if let Some(value) = c.value {
            map.insert(Code::fn_value().into(), value.into());
        }
        CborValue::Map(map)
    }
}

impl TryFrom<CborValue> for Code {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        let mut map = value
            .into_map()
            .map_err(|_| Error::Decode("Code is not a map"))?;
        let code = map
            .remove(&Code::fn_code().into())
            .ok_or(Error::Decode("code is missing code"))?
            .try_into()
            .map_err(|_| Error::Decode("code is not a string"))?;
        let sign: Option<String> = map
            .remove(&Code::fn_sign().into())
            .map(|v| {
                v.try_into()
                    .map_err(|_| Error::Decode("sign is not a string"))
            })
            .transpose()?;
        let value: Option<String> = map
            .remove(&Code::fn_value().into())
            .map(|v| {
                v.try_into()
                    .map_err(|_| Error::Decode("value is not a string"))
            })
            .transpose()?;
        Ok(Code { code, sign, value })
    }
}

impl CborSerializable for Code {}
impl AsCborValue for Code {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let value: CborValue = value.into();
        Self::try_from(value).map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "invalid Code".to_string(),
            ))
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let cbor: CborValue = self.into();
        Ok(cbor.into())
    }
}
