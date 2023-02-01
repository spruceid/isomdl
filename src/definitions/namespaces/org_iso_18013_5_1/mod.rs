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
use macros::FromJson;

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

#[cfg(test)]
mod test {
    use super::*;
    use crate::definitions::traits::FromJson;

    #[test]
    fn all() {
        // Missing biometric_template, *_national_character and signature_usual_mark as we need
        // good examples for these.
        let json = serde_json::json!({
          "family_name":"Doe",
          "given_name":"John",
          "birth_date":"1980-10-10",
          "issue_date":"2020-08-10",
          "expiry_date":"2030-10-30",
          "issuing_country":"US",
          "issuing_authority":"CA DMV",
          "document_number":"I12345678",
          "portrait":include_str!("../../../../test/issuance/portrait.b64"),
          "driving_privileges":[
            {
               "vehicle_category_code":"A",
               "issue_date":"2022-08-09",
               "expiry_date":"2030-10-20"
            },
            {
               "vehicle_category_code":"B",
               "issue_date":"2022-08-09",
               "expiry_date":"2030-10-20"
            }
          ],
          "un_distinguishing_sign":"USA",
          "administrative_number":"ABC123",
          "sex":1,
          "height":170,
          "weight":70,
          "eye_colour":"hazel",
          "hair_colour":"red",
          "birth_place":"California",
          "resident_address":"2415 1st Avenue",
          "portrait_capture_date":"2020-08-10T12:00:00Z",
          "age_in_years":42,
          "age_birth_year":1980,
          "age_over_18":true,
          "age_over_21":true,
          "issuing_jurisdiction":"US-CA",
          "nationality":"US",
          "resident_city":"Sacramento",
          "resident_state":"California",
          "resident_postal_code":"95818",
          "resident_country": "US"
        });

        let ns = OrgIso1801351::from_json(&json).unwrap();

        assert!(ns.age_over_xx.get(&('1', '8')).unwrap());
        assert!(ns.age_over_xx.get(&('2', '1')).unwrap());

        assert!(ns.administrative_number.is_some());
        assert!(ns.sex.is_some());
        assert!(ns.height.is_some());
        assert!(ns.weight.is_some());
        assert!(ns.eye_colour.is_some());
        assert!(ns.hair_colour.is_some());
        assert!(ns.birth_place.is_some());
        assert!(ns.resident_address.is_some());
        assert!(ns.portrait_capture_date.is_some());
        assert!(ns.age_in_years.is_some());
        assert!(ns.age_birth_year.is_some());
        assert!(ns.issuing_jurisdiction.is_some());
        assert!(ns.nationality.is_some());
        assert!(ns.resident_city.is_some());
        assert!(ns.resident_state.is_some());
        assert!(ns.resident_postal_code.is_some());
        assert!(ns.resident_country.is_some());
    }
}
