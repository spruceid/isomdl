use chrono::{DateTime, FixedOffset};
use either::Either;
use rust_iso3166::CountryCode;
use rust_iso3166::iso3166_2::Subdivision;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(test)]
use cddl::{lexer_from_str, parser::cddl_from_str, validate_json_from_str};

// NOTE: added quotes to keys for compatibility with JSON, e.g. 1 => "1"
//
// https://www.iana.org/assignments/cose/cose.xhtml
pub fn cose_key_cddl() -> String { r#"
COSE_Key = {
   "1" => int,          ; kty: key type
  "-1" => int,          ; crv: EC identifier - Taken from the "COSE Elliptic Curves" registry
  "-2" => tstr,         ; x: value of x-coordinate
  ? "-3" => tstr / bool ; y: value or sign bit of y-coordinate; only applicable for EC2 key types
}
"#.to_string()
}

#[cfg(test)]
mod cose_key_tests {
    use super::*;

    #[test]
    fn test_bstr() {
        let cddl = "foo = bstr";
        assert!(cddl_from_str(&mut lexer_from_str(cddl), cddl, true).is_ok());
    }

    #[test]
    fn test_validate_cose_key_cddl() {
        let input = cose_key_cddl();
        assert!(cddl_from_str(&mut lexer_from_str(&input), &input, true).is_ok())
    }

    #[test]
    fn test_validate_cose_key_json() {
        let cddl = cose_key_cddl();
        let json = r#"{
          "1": 5,
          "-1": 50,
          "-2": "846A5369676",
          "-3": false
        }"#;

        assert!(validate_json_from_str(&cddl, json).map(|_| true).unwrap())
    }
}

/// TODO
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uint {
    uint: usize,
}

/// TODO
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tdate {
    tdate: DateTime<FixedOffset>,
}

/// TODO
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullDate {}

/// TODO
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Latin1UpTo150Chars {}

/// TODO
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalBstr {}

/// TODO: fix (de)serialize
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tstr {
    tstr: String,
}



/// DrivingPrivilegeCode = {
///     ; Code as per ISO/IEC 18013-2 Annex A
///     "code": tstr
///     ; Sign as per ISO/IEC 18013-2 Annex A
///     ? "sign": tstr
///     ; Value as per ISO/IEC 18013-2 Annex A
///     ? "value": tstr
/// }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrivingPrivilegeCode {
    /// TODO: restrict to ISO/IEC 18013-2 Annex A's definition
    /// Code as per ISO/IEC 18013-2 Annex A
    code: String,
    /// TODO: restrict to ISO/IEC 18013-2 Annex A's definition
    /// Sign as per ISO/IEC 18013-2 Annex A
    sign: Option<String>,
    /// TODO: restrict to ISO/IEC 18013-2 Annex A's definition
    /// Value as per ISO/IEC 18013-2 Annex A
    value: Option<String>,
}

/// DrivingPrivilege = {
///     ; Vehicle category code as per ISO/IEC 18013-1 Annex B
///     "vehicle_category_code" : tstr
///     ; Date of issue encoded as full-date
///     ? "issue_date" : full-date
///     ; Date of expiry encoded as full-date
///     ? "expiry_date" : full-date
///     ; Array of code info
///     ? "codes" : [+DrivingPrivilegeCode]
/// }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrivingPrivilege {
    /// Vehicle category code as per ISO/IEC 18013-1 Annex B
    vehicle_category_code: Tstr,
    /// Date of issue encoded as full-date
    issue_date: Option<FullDate>,
    /// Date of expiry encoded as full-date
    expiry_date: Option<FullDate>,
    /// Array of code info
    codes: Option<Vec<DrivingPrivilegeCode>>,
}

/// ; NOTE The DrivingPrivileges structure can be an empty array.
/// DrivingPrivileges = [
///     * DrivingPrivilege
/// ]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrivingPrivileges {
    driving_privileges: Vec<DrivingPrivilege>,
}

/// TODO
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnDistinguishingSign {}

/// The four codes specified in ISO/IEC 5218 are:
/// 0 = Not known;
/// 1 = Male;
/// 2 = Female;
/// 9 = Not applicable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sex {
    /// 0
    NotKnown,
    /// 1
    Male,
    /// 2
    Female,
    /// 9
    NotApplicable,
}

/// mDL holder’s eye colour.
/// The value shall be one of the following: “black”, “blue”, “brown”, “dichromatic”, “grey”, “green”, “hazel”, “maroon”, “pink”, “unknown”.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EyeColour {
    Black,
    Blue,
    Brown,
    Dichromatic,
    Grey,
    Green,
    Hazel,
    Maroon,
    Pink,
    Unknown,
}

/// mDL holder’s hair colour.
/// The value shall be one of the following: “bald”, “black”, “blond”, “brown”, “grey”, “red”, “auburn”, “sandy”, “white”, “unknown”.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HairColour {
    Bald,
    Black,
    Blond,
    Brown,
    Grey,
    Red,
    Auburn,
    Sandy,
    White,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MdlDataElementsRaw {
    /// Last name, surname, or primary identifier, of the mDL holder.
    /// Family name
    family_name: Latin1UpTo150Chars,

    /// First name(s), other name(s), or secondary identifier, of the mDL holder.
    /// Given name
    given_name: Latin1UpTo150Chars,

    /// Day, month and year on which the mDL holder was born. If unknown, approximate date of birth
    /// Date of birth
    /// birth_date: FullDate,
    // birth_date: Tdate,
    birth_date: String,

    /// Date when mDL was issued
    /// Date of issue
    issue_date: String,

    /// Date when mDL expires
    /// Date of expiry
    expiry_date: String,

    /// Alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
    /// Issuing country
    issuing_country: String,

    /// Issuing authority name.
    /// Issuing authority
    issuing_authority: Latin1UpTo150Chars,

    /// The number assigned or calculated by the issuing authority.
    /// Licence number
    document_number: Latin1UpTo150Chars,

    /// A reproduction of the mDL holder’s portrait. See 7.2.2
    /// Portrait of mDL holder
    portrait: LocalBstr,

    /// Driving privileges of the mDL holder. See 7.2.4
    /// Categories of vehicles/ restrictions/ conditions
    driving_privileges: DrivingPrivileges,

    /// Distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F. 
    /// If no applicable distinguishing sign is available in ISO/IEC 18013-1, an
    /// IA may use an empty identifier or another identifier by which it is
    /// internationally recognized. In this case the IA should ensure there is no
    /// collision with other IA’s.
    /// Tstr
    ///
    /// UN distinguishing sign
    un_distinguishing_sign: UnDistinguishingSign,

    /// Administrative number
    /// An audit control number assigned by the issuing authority.
    administrative_number: Option<Latin1UpTo150Chars>,

    /// Sex
    /// mDL holder’s sex using values as defined in ISO/IEC 5218 .
    sex: Option<Sex>,

    /// Height (cm)^a
    /// mDL holder’s height in centimetres
    height: Option<Uint>,

    /// Weight (kg)^a
    /// mDL holder’s weight in kilograms
    weight: Option<Uint>,

    /// Eye colour
    /// mDL holder’s eye colour.
    eye_colour: Option<EyeColour>,

    /// Hair colour
    /// mDL holder’s hair colour.
    hair_colour: Option<HairColour>,

    /// Place of birth
    /// Country and municipality or state/province where the mDL holder was born.
    birth_place: Option<Latin1UpTo150Chars>,

    /// Permanent place of residence
    /// The place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).
    /// The value shall only use latin1^b characters and shall have a maximum length of 150 characters.
    resident_address: Option<Latin1UpTo150Chars>,

    /// Portrait image timestamp
    /// Date when portrait was taken
    // portrait_capture_date: Option<Tdate>,
    portrait_capture_date: Option<String>,

    /// Age attestation: How old are you (in years)?
    /// The age of the mDL holder
    age_in_years: Option<Uint>,

    /// Age attestation: In what year were you born?
    /// The year when the mDL holder was born
    age_birth_year: Option<Uint>,

    /// Age attestation: Nearest “true” attestation above request
    /// See 7.2.5
    age_over_nn: Option<bool>,

    /// TODO: ISO 3166-2:2020
    /// Issuing jurisdiction
    /// Country subdivision code of the jurisdiction that issued the mDL as defined in ISO 3166-2:2020, Clause 8.
    /// The first part of the code shall be the same as the value for issuing_country.
    issuing_jurisdiction: Option<String>,

    /// Nationality
    /// Nationality of the mDL holder as a two letter country code (alpha-2 code) defined in ISO 3166-1
    nationality: Option<String>,

    /// Resident city
    /// The city where the mDL holder lives.
    resident_city: Option<Latin1UpTo150Chars>,

    /// Resident state/province/district
    /// The state/province/district where the mDL holder lives.
    resident_state: Option<Latin1UpTo150Chars>,

    /// Resident postal code
    /// The postal code of the mDL holder.
    resident_postal_code: Option<Latin1UpTo150Chars>,

    /// Resident country
    /// The country where the mDL holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1.
    resident_country: Option<String>,

    /// TODO
    /// Biometric template XX
    /// See 7.2.6
    biometric_template_xx: Option<LocalBstr>,

    /// TODO
    /// Family name in national characters
    /// The family name of the mDL holder using full UTF-8 character set.
    family_name_national_character: Option<Tstr>,

    /// TODO
    /// Given name in national characters
    /// The given name of the mDL holder using full UTF-8 character set.
    given_name_national_character: Option<Tstr>,

    /// TODO
    /// Signature / usual mark
    /// Image of the signature or usual mark of the mDL holder, see 7.2.7
    signature_usual_mark: Option<LocalBstr>,
}

impl MdlDataElementsRaw {
    pub fn validate_country_code(alpha2_str: String) -> Result<CountryCode, MdlDataElementsError> {
        rust_iso3166::from_alpha2(&alpha2_str)
            .ok_or_else(|| MdlDataElementsError::UnexpectedCountryCode(alpha2_str))
    }

    pub fn validate_subdivision(code_str: String) -> Result<Subdivision, MdlDataElementsError> {
        rust_iso3166::iso3166_2::from_code(&code_str)
            .ok_or_else(|| MdlDataElementsError::UnexpectedSubdivision(code_str))
    }

    pub fn validate_datetime(datetime_str: String) -> Result<Tdate, MdlDataElementsError> {
        DateTime::parse_from_rfc3339(&datetime_str)
            .map_err(|e| MdlDataElementsError::UnexpectedDateTime {
                date_str: datetime_str,
                error: e,
            })
            .map(|tdate| Tdate {
                tdate: tdate,
            })
    }

    /// TODO: support Tdate
    pub fn validate_either_date(date_str: String) -> Result<Either<Tdate, FullDate>, MdlDataElementsError> {
        Ok(Either::Left(Self::validate_datetime(date_str)?))
    }



    pub fn validate(self) -> Result<MdlDataElements, MdlDataElementsError> {
        let birth_date = Self::validate_datetime(self.birth_date)?;
        let issue_date = Self::validate_either_date(self.issue_date)?;
        let expiry_date = Self::validate_either_date(self.expiry_date)?;
        let issuing_country = Self::validate_country_code(self.issuing_country)?;

        let portrait_capture_date = self.portrait_capture_date
            .map(|date_str| Self::validate_datetime(date_str)).transpose()?;

        let issuing_jurisdiction = self.issuing_jurisdiction
            .map(|code_str| Self::validate_subdivision(code_str)).transpose()?;

        let nationality = self.nationality
            .map(|alpha2_str| Self::validate_country_code(alpha2_str)).transpose()?;

        let resident_country = self.resident_country
            .map(|alpha2_str| Self::validate_country_code(alpha2_str)).transpose()?;

        Ok(MdlDataElements {
            family_name: self.family_name,
            given_name: self.given_name,
            birth_date: birth_date,
            issue_date: issue_date,
            expiry_date: expiry_date,
            issuing_country: issuing_country,
            issuing_authority: self.issuing_authority,
            document_number: self.document_number,
            portrait: self.portrait,
            driving_privileges: self.driving_privileges,
            un_distinguishing_sign: self.un_distinguishing_sign,
            administrative_number: self.administrative_number,
            sex: self.sex,
            height: self.height,
            weight: self.weight,
            eye_colour: self.eye_colour,
            hair_colour: self.hair_colour,
            birth_place: self.birth_place,
            resident_address: self.resident_address,
            portrait_capture_date: portrait_capture_date,
            age_in_years: self.age_in_years,
            age_birth_year: self.age_birth_year,
            age_over_nn: self.age_over_nn,
            issuing_jurisdiction: issuing_jurisdiction,
            nationality: nationality,
            resident_city: self.resident_city,
            resident_state: self.resident_state,
            resident_postal_code: self.resident_postal_code,
            resident_country: resident_country,
            biometric_template_xx: self.biometric_template_xx,
            family_name_national_character: self.family_name_national_character,
            given_name_national_character: self.given_name_national_character,
            signature_usual_mark: self.signature_usual_mark,
        })
    }
}

#[derive(Clone, Debug)]
pub struct MdlDataElements {
    /// Last name, surname, or primary identifier, of the mDL holder.
    /// Family name
    family_name: Latin1UpTo150Chars,

    /// First name(s), other name(s), or secondary identifier, of the mDL holder.
    /// Given name
    given_name: Latin1UpTo150Chars,

    /// Day, month and year on which the mDL holder was born. If unknown, approximate date of birth
    /// Date of birth
    /// birth_date: FullDate,
    birth_date: Tdate,

    /// Date when mDL was issued
    /// Date of issue
    issue_date: Either<Tdate, FullDate>,

    /// Date when mDL expires
    /// Date of expiry
    expiry_date: Either<Tdate, FullDate>,

    /// Alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
    /// Issuing country
    issuing_country: CountryCode,

    /// Issuing authority name.
    /// Issuing authority
    issuing_authority: Latin1UpTo150Chars,

    /// The number assigned or calculated by the issuing authority.
    /// Licence number
    document_number: Latin1UpTo150Chars,

    /// A reproduction of the mDL holder’s portrait. See 7.2.2
    /// Portrait of mDL holder
    portrait: LocalBstr,

    /// Driving privileges of the mDL holder. See 7.2.4
    /// Categories of vehicles/ restrictions/ conditions
    driving_privileges: DrivingPrivileges,

    /// Distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F. 
    /// If no applicable distinguishing sign is available in ISO/IEC 18013-1, an
    /// IA may use an empty identifier or another identifier by which it is
    /// internationally recognized. In this case the IA should ensure there is no
    /// collision with other IA’s.
    /// Tstr
    ///
    /// UN distinguishing sign
    un_distinguishing_sign: UnDistinguishingSign,

    /// Administrative number
    /// An audit control number assigned by the issuing authority.
    administrative_number: Option<Latin1UpTo150Chars>,

    /// Sex
    /// mDL holder’s sex using values as defined in ISO/IEC 5218 .
    sex: Option<Sex>,

    /// Height (cm)^a
    /// mDL holder’s height in centimetres
    height: Option<Uint>,

    /// Weight (kg)^a
    /// mDL holder’s weight in kilograms
    weight: Option<Uint>,

    /// Eye colour
    /// mDL holder’s eye colour.
    eye_colour: Option<EyeColour>,

    /// Hair colour
    /// mDL holder’s hair colour.
    hair_colour: Option<HairColour>,

    /// Place of birth
    /// Country and municipality or state/province where the mDL holder was born.
    birth_place: Option<Latin1UpTo150Chars>,

    /// Permanent place of residence
    /// The place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).
    /// The value shall only use latin1^b characters and shall have a maximum length of 150 characters.
    resident_address: Option<Latin1UpTo150Chars>,

    /// Portrait image timestamp
    /// Date when portrait was taken
    portrait_capture_date: Option<Tdate>,

    /// Age attestation: How old are you (in years)?
    /// The age of the mDL holder
    age_in_years: Option<Uint>,

    /// Age attestation: In what year were you born?
    /// The year when the mDL holder was born
    age_birth_year: Option<Uint>,

    /// Age attestation: Nearest “true” attestation above request
    /// See 7.2.5
    age_over_nn: Option<bool>,

    /// TODO: ISO 3166-2:2020
    /// Issuing jurisdiction
    /// Country subdivision code of the jurisdiction that issued the mDL as defined in ISO 3166-2:2020, Clause 8.
    /// The first part of the code shall be the same as the value for issuing_country.
    issuing_jurisdiction: Option<Subdivision>,

    /// Nationality
    /// Nationality of the mDL holder as a two letter country code (alpha-2 code) defined in ISO 3166-1
    nationality: Option<CountryCode>,

    /// Resident city
    /// The city where the mDL holder lives.
    resident_city: Option<Latin1UpTo150Chars>,

    /// Resident state/province/district
    /// The state/province/district where the mDL holder lives.
    resident_state: Option<Latin1UpTo150Chars>,

    /// Resident postal code
    /// The postal code of the mDL holder.
    resident_postal_code: Option<Latin1UpTo150Chars>,

    /// Resident country
    /// The country where the mDL holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1.
    resident_country: Option<CountryCode>,

    /// TODO
    /// Biometric template XX
    /// See 7.2.6
    biometric_template_xx: Option<LocalBstr>,

    /// TODO
    /// Family name in national characters
    /// The family name of the mDL holder using full UTF-8 character set.
    family_name_national_character: Option<Tstr>,

    /// TODO
    /// Given name in national characters
    /// The given name of the mDL holder using full UTF-8 character set.
    given_name_national_character: Option<Tstr>,

    /// TODO
    /// Signature / usual mark
    /// Image of the signature or usual mark of the mDL holder, see 7.2.7
    signature_usual_mark: Option<LocalBstr>,
}

#[derive(Clone, Debug, Error)]
pub enum MdlDataElementsError {
    #[error("UnexpectedDateTime: expected an RFC 3339 and ISO 8601 date and time string, but found: \n{date_str:?} \n\n{error}")]
    UnexpectedDateTime {
        date_str: String,
        error: chrono::format::ParseError,
    },

    #[error("Unexpected alpha-2 country code: {0:?}")]
    UnexpectedCountryCode(String),

    #[error("Unexpected ISO 3166-2 subdivision code: {0:?}")]
    UnexpectedSubdivision(String),

    // /// The value is not cached
    // #[error("Query::get_cached: value not cached:\n{name:?}\n{url:?}")]
    // NotCached {
    //     /// Query name
    //     name: String,
    //     /// Request URL
    //     url: String,
    // },

    // /// Error when running query TValue
    // #[error("TValueRunError:\n{0:?}")]
    // TValueRunError(TValueRunError),
}

// impl From<TValueRunError> for QueryError {
//     fn from(error: TValueRunError) -> Self {
//         Self::TValueRunError(error)
//     }
// }


impl MdlDataElements {
    pub fn new(family_name: Latin1UpTo150Chars,
               given_name: Latin1UpTo150Chars,
               birth_date: Tdate,
               issue_date: Either<Tdate, FullDate>,
               expiry_date: Either<Tdate, FullDate>,
               issuing_country: CountryCode,
               issuing_authority: Latin1UpTo150Chars,
               document_number: Latin1UpTo150Chars,
               portrait: LocalBstr,
               driving_privileges: DrivingPrivileges,
               un_distinguishing_sign: UnDistinguishingSign) -> Self {
        Self {
            family_name: family_name,
            given_name: given_name,
            birth_date: birth_date,
            issue_date: issue_date,
            expiry_date: expiry_date,
            issuing_country: issuing_country,
            issuing_authority: issuing_authority,
            document_number: document_number,
            portrait: portrait,
            driving_privileges: driving_privileges,
            un_distinguishing_sign: un_distinguishing_sign,
            administrative_number: None,
            sex: None,
            height: None,
            weight: None,
            eye_colour: None,
            hair_colour: None,
            birth_place: None,
            resident_address: None,
            portrait_capture_date: None,
            age_in_years: None,
            age_birth_year: None,
            age_over_nn: None,
            issuing_jurisdiction: None,
            nationality: None,
            resident_city: None,
            resident_state: None,
            resident_postal_code: None,
            resident_country: None,
            biometric_template_xx: None,
            family_name_national_character: None,
            given_name_national_character: None,
            signature_usual_mark: None,
        }
    }

    // /// Attempt to convert from JSON
    // pub fn from_json(json: Value) -> Result<MdlDataElementsError, Self> {
    //     let json_object = json.as_object().or_else(|| MdlDataElementsError::NotObject(json));
    //     json_object

    //     // Self::new(family_name: Latin1UpTo150Chars,
    //     //           given_name: Latin1UpTo150Chars,
    //     //           birth_date: Tdate,
    //     //           issue_date: Either<Tdate, FullDate>,
    //     //           expiry_date: Either<Tdate, FullDate>,
    //     //           issuing_country: CountryCode,
    //     //           issuing_authority: Latin1UpTo150Chars,
    //     //           document_number: Latin1UpTo150Chars,
    //     //           portrait: LocalBstr,
    //     //           driving_privileges: DrivingPrivileges,
    //     //           un_distinguishing_sign: UnDistinguishingSign) -> Self {

    //     _
    // }
}

#[cfg(test)]
mod mdl_data_elements_tests {
    // use super::*;

    // #[test]
    // fn test_mdl_data_elements() {
    //     let cddl = mdl_data_elements_cddl();
    //     println!("Raw CDDL:\n{}\n", cddl);
    //     assert!(cddl_from_str(&mut lexer_from_str(&cddl), &cddl, true).is_ok());

    //     let json = r#"{
    //       "family_name": "Bob",
    //       "given_name": "Alicé",
    //       "birth_date": "2022-11-11T22:22:50.52Z",
    //       "issue_date": "2022-11-11T22:22:50.52Z",
    //       "expiry_date": "2022-11-11T22:22:50.52Z",
    //       "issuing_country": "USA",
    //       "issuing_authority": "Some Issuing Authority",
    //       "document_number": "1234",
    //       "portrait": "0xFFFFF",
    //       "driving_privileges": [],
    //       "un_distinguishing_sign": "USA",
    //       "eye_colour": "unknown",
    //       "hair_colour": "unknown",
    //       "nationality": "US",
    //       "issuing_jurisdiction": "US-NY"
    //     }"#;

    //     assert!(validate_json_from_str(&cddl, json).map(|_| true).unwrap())
    // }
}


pub fn mdl_data_elements_cddl() -> String {
    let mut cddl_str = r#"
        MdlDataElements = {
            ; Last name, surname, or primary identifier, of the mDL holder.
            ; Family name
            family_name: latin1-up-to-150-chars,

            ; First name(s), other name(s), or secondary identifier, of the mDL holder.
            ; Given name
            ;
            ; TODO: note support for or-empty
            given_name: latin1-up-to-150-chars-or-empty,

            ; TODO: full-date not supported by (rust)-cddl?
            ; Day, month and year on which the mDL holder was born. If unknown, approximate date of birth
            ; Date of birth
            ; birth_date: full-date,
            birth_date: tdate,

            ; Date when mDL was issued
            ; Date of issue
            issue_date: tdate / full-date,

            ; Date when mDL expires
            ; Date of expiry
            expiry_date: tdate / full-date,

            ; Alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
            ; Issuing country
            issuing_country: alpha-2-country-code,

            ; Issuing authority name.
            ; Issuing authority
            issuing_authority: latin1-up-to-150-chars,

            ; The number assigned or calculated by the issuing authority.
            ; Licence number
            document_number: latin1-up-to-150-chars,

            ; A reproduction of the mDL holder’s portrait. See 7.2.2
            ; Portrait of mDL holder
            portrait: local-bstr,

            ; Driving privileges of the mDL holder. See 7.2.4
            ; Categories of vehicles/ restrictions/ conditions
            driving_privileges: DrivingPrivileges,

            ; Distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F. 
            ; If no applicable distinguishing sign is available in ISO/IEC 18013-1, an
            ; IA may use an empty identifier or another identifier by which it is
            ; internationally recognized. In this case the IA should ensure there is no
            ; collision with other IA’s.
            ; tstr
            ;
            ; UN distinguishing sign
            un_distinguishing_sign: un-distinguishing-sign,

            ; Administrative number
            ; An audit control number assigned by the issuing authority.
            ? administrative_number: latin1-up-to-150-chars,

            ; The four codes specified in ISO/IEC 5218 are:
            ; 0 = Not known;
            ; 1 = Male;
            ; 2 = Female;
            ; 9 = Not applicable.
            ;
            ; Sex
            ; mDL holder’s sex using values as defined in ISO/IEC 5218 .
            ? sex: uint,

            ; Height (cm)^a
            ; mDL holder’s height in centimetres
            ? height: uint,

            ; Weight (kg)^a
            ; mDL holder’s weight in kilograms
            ? weight: uint,

            ; Eye colour
            ; mDL holder’s eye colour.
            ? eye_colour: eye-colour,

            ; Hair colour
            ; mDL holder’s hair colour.
            ? hair_colour: hair-colour,

            ; Place of birth
            ; Country and municipality or state/province where the mDL holder was born.
            ? birth_place: latin1-up-to-150-chars,

            ; Permanent place of residence
            ; The place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).
            ; The value shall only use latin1^b characters and shall have a maximum length of 150 characters.
            ? resident_address: latin1-up-to-150-chars,

            ; Portrait image timestamp
            ; Date when portrait was taken
            ? portrait_capture_date: tdate,

            ; Age attestation: How old are you (in years)?
            ; The age of the mDL holder
            ? age_in_years: uint,

            ; Age attestation: In what year were you born?
            ; The year when the mDL holder was born
            ? age_birth_year: uint,

            ; Age attestation: Nearest “true” attestation above request
            ; See 7.2.5
            ? age_over_NN: bool,

            ; Issuing jurisdiction
            ; Country subdivision code of the jurisdiction that issued the mDL as defined in ISO 3166-2:2020, Clause 8.
            ; The first part of the code shall be the same as the value for issuing_country.
            ? issuing_jurisdiction: country-subdivision-code,

            ; Nationality
            ; Nationality of the mDL holder as a two letter country code (alpha-2 code) defined in ISO 3166-1
            ? nationality: alpha-2-country-code,

            ; Resident city
            ; The city where the mDL holder lives.
            ? resident_city: latin1-up-to-150-chars,

            ; Resident state/province/district
            ; The state/province/district where the mDL holder lives.
            ? resident_state: latin1-up-to-150-chars,

            ; Resident postal code
            ; The postal code of the mDL holder.
            ? resident_postal_code: latin1-up-to-150-chars,

            ; Resident country
            ; The country where the mDL holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1.
            ? resident_country: alpha-2-country-code,

            ; TODO: bstr + biometric_template_xx
            ; Biometric template XX
            ; See 7.2.6
            ? biometric_template_xx: local-bstr,

            ; TODO
            ; Family name in national characters
            ; The family name of the mDL holder using full UTF-8 character set.
            ? family_name_national_character: tstr,

            ; TODO
            ; Given name in national characters
            ; The given name of the mDL holder using full UTF-8 character set.
            ? given_name_national_character: tstr,

            ; TODO
            ; Signature / usual mark
            ; Image of the signature or usual mark of the mDL holder, see 7.2.7
            ? signature_usual_mark: local-bstr,

        }

        ; mDL holder’s eye colour.
        ; The value shall be one of the following: “black”, “blue”, “brown”, “dichromatic”, “grey”, “green”, “hazel”, “maroon”, “pink”, “unknown”.
        eye-colour = tstr .regexp "(black|blue|brown|dichromatic|grey|green|hazel|maroon|pink|unknown)"

        ; The value shall be one of the following: “bald”, “black”, “blond”, “brown”, “grey”, “red”, “auburn”, “sandy”, “white”, “unknown”.
        hair-colour = tstr .regexp "(bald|black|blond|brown|grey|red|auburn|sandy|white|unknown)"

        ; TODO: implement
        ; Distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F. 
        ; If no applicable distinguishing sign is available in ISO/IEC 18013-1, an
        ; IA may use an empty identifier or another identifier by which it is
        ; internationally recognized. In this case the IA should ensure there is no
        ; collision with other IA’s.
        ;
        ; UN distinguishing sign
        un-distinguishing-sign = tstr

        ; TODO: extend regex
        ; The value shall only use latin1^b characters and shall have a maximum length of 150 characters.
        latin1-up-to-150-chars = tstr .regexp "[0-9A-z\u00C0-\u00ff]{1, 150}"

        ; TODO: extend regex a la latin1-up-to-150-chars
        ; The value shall only use latin1^b characters and shall have a maximum length of 150 characters.
        latin1-up-to-150-chars-or-empty = tstr .regexp "[0-9A-z\u00C0-\u00ff]{0, 150}"

        ; TODO: implement CBOR-friendly version
        local-bstr = tstr .regexp "0x[0-9a-fA-F]*"

        ; TODO: non-empty array
        ; NOTE The DrivingPrivileges structure can be an empty array.
        DrivingPrivileges = [
            * DrivingPrivilege
        ]

        DrivingPrivilege = {
            ; Vehicle category code as per ISO/IEC 18013-1 Annex B
            "vehicle_category_code" : tstr
            ; Date of issue encoded as full-date
            ? "issue_date" : full-date
            ; Date of expiry encoded as full-date
            ? "expiry_date" : full-date
            ; Array of code info
            ? "codes" : [+Code]
        }

        ; a.k.a. "DrivingPrivilegeCode"
        Code = {
            ; TODO: implement ISO/IEC 18013-2 Annex A
            ; Code as per ISO/IEC 18013-2 Annex A
            "code": tstr
            ; Sign as per ISO/IEC 18013-2 Annex A
            ? "sign": tstr
            ; Value as per ISO/IEC 18013-2 Annex A
            ? "value": tstr
        }
        "#.to_string();

    let mut regex_prefix = "(";
    let mut alpha_2_country_code_cddl = "\n".to_string();
    alpha_2_country_code_cddl.push_str("; A two letter country code (alpha-2 code) defined in ISO 3166-1.\n");
    alpha_2_country_code_cddl.push_str("alpha-2-country-code = tstr .regexp \"");
    for country_code in rust_iso3166::ALL {
        alpha_2_country_code_cddl.push_str(&format!("{}{}", regex_prefix, country_code.alpha2));
        regex_prefix = "|"
    }
    alpha_2_country_code_cddl.push_str(")\"");
    cddl_str.push_str(&alpha_2_country_code_cddl);

    regex_prefix = "(";
    let mut country_subdivision_code_cddl = "\n".to_string();
    country_subdivision_code_cddl.push_str("; A country subdivision code defined in ISO 3166-2.\n");
    country_subdivision_code_cddl.push_str("country-subdivision-code = tstr .regexp \"");
    for country_code in rust_iso3166::ALL {
        // TODO: is this the correct ISO 3166-2 code?
        // Also available besides .code are: .name, .region_code, etc.
        for subdivision in country_code.subdivisions()
            .expect(&format!("missing country subdivision codes for: {}", country_code.alpha2)) {
            country_subdivision_code_cddl.push_str(&format!("{}{}", regex_prefix, subdivision.code));
            regex_prefix = "|"
        }
    }
    country_subdivision_code_cddl.push_str(")\"");
    cddl_str.push_str(&country_subdivision_code_cddl);

    cddl_str
}

#[cfg(test)]
mod mdl_data_elements_json_tests {
    use super::*;

    #[test]
    fn test_mdl_data_elements() {
        let cddl = mdl_data_elements_cddl();
        println!("Raw CDDL:\n{}\n", cddl);
        assert!(cddl_from_str(&mut lexer_from_str(&cddl), &cddl, true).is_ok());

        let json = r#"{
          "family_name": "Bob",
          "given_name": "Alicé",
          "birth_date": "2022-11-11T22:22:50.52Z",
          "issue_date": "2022-11-11T22:22:50.52Z",
          "expiry_date": "2022-11-11T22:22:50.52Z",
          "issuing_country": "USA",
          "issuing_authority": "Some Issuing Authority",
          "document_number": "1234",
          "portrait": "0xFFFFF",
          "driving_privileges": [],
          "un_distinguishing_sign": "USA",
          "eye_colour": "unknown",
          "hair_colour": "unknown",
          "nationality": "US",
          "issuing_jurisdiction": "US-NY"
        }"#;

        assert!(validate_json_from_str(&cddl, json).map(|_| true).unwrap())
    }
}

