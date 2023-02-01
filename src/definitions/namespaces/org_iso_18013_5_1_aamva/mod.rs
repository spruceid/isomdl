#![allow(non_snake_case)]

mod county_code;
mod dhs_compliance;
mod domestic_driving_privileges;
mod edl_indicator;
mod name_suffix;
mod name_truncation;
mod present;
mod race_and_ethnicity;
mod sex;
mod weight_range;

pub use super::{fulldate::FullDate, latin1::Latin1};
pub use county_code::CountyCode;
pub use dhs_compliance::DHSCompliance;
pub use domestic_driving_privileges::*;
pub use edl_indicator::EDLIndicator;
pub use name_suffix::NameSuffix;
pub use name_truncation::NameTruncation;
pub use present::Present;
pub use race_and_ethnicity::RaceAndEthnicity;
pub use sex::Sex;
pub use weight_range::WeightRange;

use macros::FromJson;

#[derive(Debug, Clone, FromJson)]
pub struct OrgIso1801351Aamva {
    pub domestic_driving_privileges: DomesticDrivingPrivileges,
    pub name_suffix: Option<NameSuffix>,
    pub organ_donor: Option<Present>,
    pub veteran: Option<Present>,
    pub family_name_truncation: NameTruncation,
    pub given_name_truncation: NameTruncation,
    pub aka_suffix: Option<NameSuffix>,
    pub weight_range: Option<WeightRange>,
    pub race_ethnicity: Option<RaceAndEthnicity>,
    pub DHS_compliance: Option<DHSCompliance>,
    pub DHS_temporary_lawful_status: Option<Present>,
    pub EDL_credential: Option<EDLIndicator>,
    pub resident_county: Option<CountyCode>,
    pub hazmat_endorsement_expiration_date: Option<FullDate>,
    pub sex: Sex,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::definitions::traits::FromJson;

    #[test]
    fn all() {
        let json = serde_json::json!({
          "domestic_driving_privileges":[
            {
              "domestic_vehicle_class":{
                "domestic_vehicle_class_code":"A",
                "domestic_vehicle_class_description":"unknown",
                "issue_date":"2022-08-09",
                "expiry_date":"2030-10-20"
              }
            },
            {
              "domestic_vehicle_class":{
                "domestic_vehicle_class_code":"B",
                "domestic_vehicle_class_description":"unknown",
                "issue_date":"2022-08-09",
                "expiry_date":"2030-10-20"
              }
            }
          ],
          "name_suffix":"1ST",
          "organ_donor":1,
          "veteran":1,
          "family_name_truncation":"N",
          "given_name_truncation":"N",
          "aka_suffix":"I",
          "weight_range":3,
          "race_ethnicity":"AI",
          "DHS_compliance":"F",
          "DHS_temporary_lawful_status":1,
          "EDL_credential":1,
          "resident_county":"013",
          "hazmat_endorsement_expiration_date":"2024-01-30",
          "sex":2
        });

        let ns = OrgIso1801351Aamva::from_json(&json).unwrap();

        assert!(ns.name_suffix.is_some());
        assert!(ns.organ_donor.is_some());
        assert!(ns.veteran.is_some());
        assert!(ns.aka_suffix.is_some());
        assert!(ns.weight_range.is_some());
        assert!(ns.race_ethnicity.is_some());
        assert!(ns.DHS_compliance.is_some());
        assert!(ns.DHS_temporary_lawful_status.is_some());
        assert!(ns.EDL_credential.is_some());
        assert!(ns.resident_county.is_some());
        assert!(ns.hazmat_endorsement_expiration_date.is_some());
    }
}
