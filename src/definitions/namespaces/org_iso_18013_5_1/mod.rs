mod age_over;
mod alpha2;
mod biometric_template;
mod driving_privileges;
mod eye_colour;
mod hair_colour;
mod issuing_jurisdiction;
mod sex;
mod tdate;
mod un_distinguishing_sign;

pub use super::{fulldate::FullDate, latin1::Latin1};

pub use age_over::AgeOver;
pub use alpha2::Alpha2;
pub use biometric_template::BiometricTemplate;
pub use driving_privileges::*;
pub use eye_colour::EyeColour;
pub use hair_colour::HairColour;
pub use issuing_jurisdiction::IssuingJurisdiction;
pub use sex::Sex;
pub use tdate::{TDate, TDateOrFullDate};
pub use un_distinguishing_sign::UNDistinguishingSign;

use crate::definitions::{
    helpers::ByteStr,
};

#[derive(Debug, Clone, FromJson)]
pub struct OrgIso18013_5 {
    family_name: Latin1,
    given_name: Latin1,
    birth_date: FullDate,
    issue_date: TDateOrFullDate,
    expiry_date: TDateOrFullDate,
    issuing_country: Alpha2,
    issuing_authority: Latin1,
    document_number: Latin1,
    portrait: ByteStr,
    driving_privileges: DrivingPrivileges,
    un_distinguishing_sign: UNDistinguishingSign,
    administrative_number: Option<Latin1>,
    sex: Option<Sex>,
    height: Option<u32>,
    weight: Option<u32>,
    eye_colour: Option<EyeColour>,
    hair_colour: Option<HairColour>,
    birth_place: Option<Latin1>,
    resident_address: Option<Latin1>,
    portrait_capture_date: Option<TDate>,
    age_in_years: Option<u32>,
    age_birth_year: Option<u32>,
    #[dynamic_fields]
    age_over_xx: AgeOver,
    #[dynamic_fields]
    issuing_jurisdiction: Option<IssuingJurisdiction>,
    nationality: Option<Alpha2>,
    resident_city: Option<Latin1>,
    resident_state: Option<Latin1>,
    resident_postal_code: Option<Latin1>,
    resident_country: Option<Alpha2>,
    #[dynamic_fields]
    biometric_template_xx: BiometricTemplate,
    family_name_national_character: Option<String>,
    given_name_national_character: Option<String>,
    signature_usual_mark: Option<ByteStr>
}
