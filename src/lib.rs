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

pub fn mdl_data_elements_cddl() -> String { r#"
MdlDataElements = {
  family_name: tstr,
  issue_date: tdate / full-date,
? eye_colour: tstr,
}
"#.to_string()
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

#[cfg(test)]
mod mdl_data_elements_tests {
    use super::*;

    #[test]
    fn test_mdl_data_elements() {
        let cddl = mdl_data_elements_cddl();
        assert!(cddl_from_str(&mut lexer_from_str(&cddl), &cddl, true).is_ok());

        let json = r#"{
          "family_name": "Bob",
          "issue_date": "2022-11-11T22:22:50.52Z"
        }"#;

        assert!(validate_json_from_str(&cddl, json).map(|_| true).unwrap())
    }

}

