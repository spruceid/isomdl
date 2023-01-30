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

#[derive(Debug, Clone, FromJson)]
#[allow(non_snake_case)]
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
