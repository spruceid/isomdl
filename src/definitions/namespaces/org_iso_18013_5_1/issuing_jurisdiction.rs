use crate::definitions::{
    namespaces::org_iso_18013_5_1::Alpha2,
    traits::{FromMap, FromJson, FromJsonError}
};
use serde_json::{Value, Map};

#[derive(Debug, Clone)]
pub struct IssuingJurisdiction(String);

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("issuing_jurisdiction must start with the value of issuing_country")]
    CountryMismatch
}

impl FromMap for IssuingJurisdiction {
    fn from_map(map: &Map<String, Value>) -> Result<Self, FromJsonError> {
        let jurisdiction = map.get("issuing_jurisdiction")
            .ok_or(FromJsonError::Missing)
            .and_then(String::from_json)?;

        let country = map.get("issuing_country")
            .ok_or(FromJsonError::Missing)
            .and_then(Alpha2::from_json)?;

        if !jurisdiction.starts_with(country.as_str()) {
            return Err(Error::CountryMismatch).map_err(Into::into).map_err(FromJsonError::Parsing)
        }

        Ok(Self(jurisdiction))
    }
}
