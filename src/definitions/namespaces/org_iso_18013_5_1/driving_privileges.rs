use super::FullDate;
use crate::definitions::helpers::NonEmptyVec;
use serde_cbor::Value as Cbor;
use std::collections::BTreeMap;

pub type DrivingPrivileges = Vec<DrivingPrivilege>;

#[derive(Clone, Debug, FromJson)]
pub struct DrivingPrivilege {
    pub vehicle_category_code: String,
    pub issue_date: Option<FullDate>,
    pub expiry_date: Option<FullDate>,
    pub codes: Option<NonEmptyVec<Code>>,
}

#[derive(Clone, Debug, FromJson)]
pub struct Code {
    pub code: String,
    pub sign: Option<String>,
    pub value: Option<String>,
}

impl From<DrivingPrivilege> for Cbor {
    fn from(d: DrivingPrivilege) -> Cbor {
        let mut map = BTreeMap::new();
        map.insert(
            "vehicle_category_code".to_string().into(),
            d.vehicle_category_code.into(),
        );
        if let Some(issue_date) = d.issue_date {
            map.insert("issue_date".to_string().into(), issue_date.into());
        }
        if let Some(expiry_date) = d.expiry_date {
            map.insert("expiry_date".to_string().into(), expiry_date.into());
        }
        if let Some(codes) = d.codes {
            map.insert(
                "codes".to_string().into(),
                codes
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

impl From<Code> for Cbor {
    fn from(c: Code) -> Cbor {
        let mut map = BTreeMap::new();
        map.insert("code".to_string().into(), c.code.into());
        if let Some(sign) = c.sign {
            map.insert("sign".to_string().into(), sign.into());
        }
        if let Some(value) = c.value {
            map.insert("value".to_string().into(), value.into());
        }
        Cbor::Map(map)
    }
}
