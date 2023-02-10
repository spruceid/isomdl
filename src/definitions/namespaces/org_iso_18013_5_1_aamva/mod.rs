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

/// `org.iso.18013.5.1.aamva` namespace, as per the AAMVA mDL Implementation
/// Guidelines (Version 1.2).
#[derive(Debug, Clone, FromJson)]
pub struct OrgIso1801351Aamva {
    pub domestic_driving_privileges: DomesticDrivingPrivileges,
    pub name_suffix: Option<NameSuffix>,
    pub organ_donor: Option<Present>,
    pub veteran: Option<Present>,
    pub family_name_truncation: NameTruncation,
    pub given_name_truncation: NameTruncation,
    #[rename("aka_family_name.v2")]
    pub aka_family_name_v2: Option<Latin1>,
    #[rename("aka_given_name.v2")]
    pub aka_given_name_v2: Option<Latin1>,
    pub aka_suffix: Option<NameSuffix>,
    pub weight_range: Option<WeightRange>,
    pub race_ethnicity: Option<RaceAndEthnicity>,
    #[rename("EDL_credential")]
    pub edl_credential: Option<EDLIndicator>,
    pub sex: Sex,
    #[rename("DHS_compliance")]
    pub dhs_compliance: DHSCompliance,
    pub resident_county: Option<CountyCode>,
    pub hazmat_endorsement_expiration_date: Option<FullDate>,
    #[rename("CDL_indicator")]
    pub cdl_indicator: Option<Present>,
    #[rename("DHS_compliance_text")]
    pub dhs_compliance_text: Option<String>,
    #[rename("DHS_temporary_lawful_status")]
    pub dhs_temporary_lawful_status: Option<Present>,
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
          "aka_family_name.v2":"Doe",
          "aka_given_name.v2":"John",
          "aka_suffix":"I",
          "weight_range":3,
          "race_ethnicity":"AI",
          "EDL_credential":1,
          "sex":2,
          "DHS_compliance":"F",
          "resident_county":"013",
          "hazmat_endorsement_expiration_date":"2024-01-30",
          "CDL_indicator":1,
          "DHS_compliance_text":"Compliant",
          "DHS_temporary_lawful_status":1,
        });

        let ns = OrgIso1801351Aamva::from_json(&json).unwrap();

        assert!(ns.name_suffix.is_some());
        assert!(ns.organ_donor.is_some());
        assert!(ns.veteran.is_some());
        assert!(ns.aka_suffix.is_some());
        assert!(ns.weight_range.is_some());
        assert!(ns.race_ethnicity.is_some());
        assert!(ns.edl_credential.is_some());
        assert!(ns.resident_county.is_some());
        assert!(ns.hazmat_endorsement_expiration_date.is_some());
        assert!(ns.cdl_indicator.is_some());
        assert!(ns.dhs_compliance_text.is_some());
        assert!(ns.dhs_temporary_lawful_status.is_some());
    }
}
