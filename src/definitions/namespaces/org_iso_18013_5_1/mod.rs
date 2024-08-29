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

use crate::{
    definitions::helpers::ByteStr,
    macros::{FromJson, ToCbor},
};

/// The `org.iso.18013.5.1` namespace.
// todo: use ToCbor
// #[derive(Debug, Clone, FromJson, ToCbor)]
#[derive(Debug, Clone, FromJson)]
#[isomdl(crate = "crate")]
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
    #[isomdl(many)]
    pub age_over_xx: AgeOver,
    #[isomdl(dynamic_parse)]
    pub issuing_jurisdiction: Option<IssuingJurisdiction>,
    pub nationality: Option<Alpha2>,
    pub resident_city: Option<Latin1>,
    pub resident_state: Option<Latin1>,
    pub resident_postal_code: Option<Latin1>,
    pub resident_country: Option<Alpha2>,
    #[isomdl(many)]
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
          "family_name":"Smith",
          "given_name":"Alice",
          "birth_date":"1980-01-01",
          "issue_date":"2020-01-01",
          "expiry_date":"2030-01-01",
          "issuing_country":"US",
          "issuing_authority":"NY DMV",
          "document_number":"DL12345678",
          "portrait":include_str!("../../../../test/issuance/portrait.b64"),
          "driving_privileges":[
            {
               "vehicle_category_code":"A",
               "issue_date":"2020-01-01",
               "expiry_date":"2030-01-01"
            },
            {
               "vehicle_category_code":"B",
               "issue_date":"2020-01-01",
               "expiry_date":"2030-01-01"
            }
          ],
          "un_distinguishing_sign":"USA",
          "administrative_number":"ABC123",
          "sex":1,
          "height":170,
          "weight":70,
          "eye_colour":"hazel",
          "hair_colour":"red",
          "birth_place":"Canada",
          "resident_address":"138 Eagle Street",
          "portrait_capture_date":"2020-01-01T12:00:00Z",
          "age_in_years":43,
          "age_birth_year":1980,
          "age_over_18":true,
          "age_over_21":true,
          "issuing_jurisdiction":"US-NY",
          "nationality":"US",
          "resident_city":"Albany",
          "resident_state":"New York",
          "resident_postal_code":"12202-1719",
          "resident_country": "US"
        });

        let ns = OrgIso1801351::from_json(&json).unwrap();

        assert!(ns.age_over_xx.get(&18.try_into().unwrap()).unwrap());
        assert!(ns.age_over_xx.get(&21.try_into().unwrap()).unwrap());

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
