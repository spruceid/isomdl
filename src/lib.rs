use either::Either;

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

        // let json = "\"''\"";
        // assert!(validate_json_from_str(cddl, json).map(|_| true).unwrap())
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

pub struct Uint {
    uint: usize,
}

pub struct Tdate {}
pub struct FullDate {}

pub struct Latin1UpTo150Chars {}
pub struct LocalBstr {}
pub struct Tstr {}
pub struct DrivingPrivileges {}
pub struct UnDistinguishingSign {}

/// The four codes specified in ISO/IEC 5218 are:
/// 0 = Not known;
/// 1 = Male;
/// 2 = Female;
/// 9 = Not applicable.
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

pub struct MdlDataElements {
    // family_name: String,
    // issue_date: Either<Tdate, FullDate>,

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
    issuing_country: Tstr,

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
    age_over_NN: Option<bool>,

    /// Issuing jurisdiction
    /// Country subdivision code of the jurisdiction that issued the mDL as defined in ISO 3166-2:2020, Clause 8.
    /// The first part of the code shall be the same as the value for issuing_country.
    issuing_jurisdiction: Option<Tstr>,

    /// TODO
    /// Nationality
    /// Nationality of the mDL holder as a two letter country code (alpha-2 code) defined in ISO 3166-1
    nationality: Option<Tstr>,

    /// Resident city
    /// The city where the mDL holder lives.
    resident_city: Option<Latin1UpTo150Chars>,

    /// Resident state/province/district
    /// The state/province/district where the mDL holder lives.
    resident_state: Option<Latin1UpTo150Chars>,

    /// Resident postal code
    /// The postal code of the mDL holder.
    resident_postal_code: Option<Latin1UpTo150Chars>,

    /// TODO
    /// Resident country
    /// The country where the mDL holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1.
    resident_country: Option<Tstr>,

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

pub fn mdl_data_elements_cddl() -> String { r#"
MdlDataElements = {
    ; Last name, surname, or primary identifier, of the mDL holder.
    ; Family name
    family_name: latin1-up-to-150-chars,

    ; First name(s), other name(s), or secondary identifier, of the mDL holder.
    ; Given name
    ;
    ; TODO: or-empty?
    given_name: latin1-up-to-150-chars,

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
    issuing_country: tstr,

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
    driving_privileges: driving-privileges,

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
    ? issuing_jurisdiction: tstr,

    ; TODO
    ; Nationality
    ; Nationality of the mDL holder as a two letter country code (alpha-2 code) defined in ISO 3166-1
    ? nationality: tstr,

    ; Resident city
    ; The city where the mDL holder lives.
    ? resident_city: latin1-up-to-150-chars,

    ; Resident state/province/district
    ; The state/province/district where the mDL holder lives.
    ? resident_state: latin1-up-to-150-chars,

    ; Resident postal code
    ; The postal code of the mDL holder.
    ? resident_postal_code: latin1-up-to-150-chars,

    ; TODO
    ; Resident country
    ; The country where the mDL holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1.
    ? resident_country: tstr,

    ; TODO
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
; latin1-up-to-150-chars-or-empty = tstr .regexp "[0-9A-z\u00C0-\u00ff]{0, 150}"

; TODO
local-bstr = tstr .regexp "0x[0-9a-fA-F]*"

; TODO
driving-privileges = tstr
"#.to_string()
}

#[cfg(test)]
mod mdl_data_elements_tests {
    use super::*;

    #[test]
    fn test_mdl_data_elements() {
        let cddl = mdl_data_elements_cddl();
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
          "driving_privileges": "[driving_privileges]",
          "un_distinguishing_sign": "USA",
          "eye_colour": "unknown",
          "hair_colour": "unknown"
        }"#;

        assert!(validate_json_from_str(&cddl, json).map(|_| true).unwrap())
    }
}

