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

pub struct Tdate {}
pub struct FullDate {}

pub struct MdlDataElements {
    /// Meaning: Family name
    /// Definition: Last name, surname, or primary identifier of the mDL holder
    /// The value shall only use latin1b characters and shall have a maximum length of 150 characters.
    family_name: String,
    issue_date: Either<Tdate, FullDate>,
}

pub fn mdl_data_elements_cddl() -> String { r#"
MdlDataElements = {
    ; Last name, surname, or primary identifier, of the mDL holder.
    ; Family name
    family_name: latin1-up-to-150-chars,

    ; First name(s), other name(s), or secondary identifier, of the mDL holder.
    ; Given names
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

    ? eye_colour: tstr,
}

; TODO: extend regex
; The value shall only use latin1^b characters and shall have a maximum length of 150 characters.
latin1-up-to-150-chars = tstr .regexp "[0-9A-z\u00C0-\u00ff]{1, 150}"

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
          "driving_privileges": "[driving_privileges]"
        }"#;

        assert!(validate_json_from_str(&cddl, json).map(|_| true).unwrap())
    }
}

