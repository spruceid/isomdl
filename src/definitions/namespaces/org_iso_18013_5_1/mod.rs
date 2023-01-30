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

use crate::definitions::helpers::ByteStr;

#[derive(Debug, Clone, FromJson)]
pub struct OrgIso1801351 {
    pub family_name: Latin1,
    pub given_name: Latin1,
    pub birth_date: FullDate,
    pub issue_date: TDateOrFullDate,
    pub expiry_date: TDateOrFullDate,
    pub issuing_country: Alpha2,
    pub issuing_authority: Latin1,
    pub document_number: Latin1,
    pub portrait: ByteStr,
    pub driving_privileges: DrivingPrivileges,
    pub un_distinguishing_sign: UNDistinguishingSign,
    pub administrative_number: Option<Latin1>,
    pub sex: Option<Sex>,
    pub height: Option<u32>,
    pub weight: Option<u32>,
    pub eye_colour: Option<EyeColour>,
    pub hair_colour: Option<HairColour>,
    pub birth_place: Option<Latin1>,
    pub resident_address: Option<Latin1>,
    pub portrait_capture_date: Option<TDate>,
    pub age_in_years: Option<u32>,
    pub age_birth_year: Option<u32>,
    #[dynamic_fields]
    pub age_over_xx: AgeOver,
    #[dynamic_fields]
    pub issuing_jurisdiction: Option<IssuingJurisdiction>,
    pub nationality: Option<Alpha2>,
    pub resident_city: Option<Latin1>,
    pub resident_state: Option<Latin1>,
    pub resident_postal_code: Option<Latin1>,
    pub resident_country: Option<Alpha2>,
    #[dynamic_fields]
    pub biometric_template_xx: BiometricTemplate,
    pub family_name_national_character: Option<String>,
    pub given_name_national_character: Option<String>,
    pub signature_usual_mark: Option<ByteStr>,
}
