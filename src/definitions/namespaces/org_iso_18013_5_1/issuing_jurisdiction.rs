use crate::definitions::{
    namespaces::org_iso_18013_5_1::Alpha2,
    traits::{FromJson, FromJsonError, FromJsonMap},
};
use serde_json::{Map, Value as Json};

/// `issuing_jurisdiction` in the org.iso.18013.5.1 namespace.
#[derive(Debug, Clone)]
pub struct IssuingJurisdiction(String);

impl IssuingJurisdiction {
    pub fn new(issuing_jurisdiction: String, issuing_country: Alpha2) -> Result<Self, Error> {
        if !issuing_jurisdiction.starts_with(issuing_country.as_str()) {
            return Err(Error::CountryMismatch);
        }
        Ok(Self(issuing_jurisdiction))
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("issuing_jurisdiction must start with the value of issuing_country")]
    CountryMismatch,
}

impl From<Error> for FromJsonError {
    fn from(e: Error) -> Self {
        FromJsonError::Parsing(e.into())
    }
}

impl From<IssuingJurisdiction> for ciborium::Value {
    fn from(i: IssuingJurisdiction) -> ciborium::Value {
        i.0.into()
    }
}

impl FromJsonMap for IssuingJurisdiction {
    fn from_map(map: &Map<String, Json>) -> Result<Self, FromJsonError> {
        let jurisdiction = map
            .get("issuing_jurisdiction")
            .ok_or(FromJsonError::Missing)
            .and_then(String::from_json)?;

        let country = map
            .get("issuing_country")
            .ok_or(FromJsonError::Missing)
            .and_then(Alpha2::from_json)?;

        Ok(Self::new(jurisdiction, country)?)
    }
}
