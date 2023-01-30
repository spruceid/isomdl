use serde_json::Value;
use std::{ops::Deref, str::FromStr};

use crate::definitions::traits::{FromJson, FromJsonError};

/// A string of up to 150 characters from ISO/IEC 8859-1 Latin alphabet 1.
///
/// Note that this struct only validates that the characters within the internal UTF-8 encoded
/// string are in the Latin 1 alphabet, and that the encoding for this data is still UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Latin1(String);

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("contains characters that are not in the Latin1 alphabet: {0:?}")]
    NonLatin1(Vec<char>),
    #[error("contains more than 150 characters: {0}")]
    TooLong(usize),
}

impl Deref for Latin1 {
    type Target = String;

    fn deref(&self) -> &String {
        &self.0
    }
}

impl FromJson for Latin1 {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        String::from_json(v)?
            .parse()
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}

impl FromStr for Latin1 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Latin1, Error> {
        let length = s.len();
        if length > 150 {
            return Err(Error::TooLong(length));
        }

        let non_latin: Vec<char> = s.chars().filter(|c| !is_latin(c)).collect();

        if !non_latin.is_empty() {
            return Err(Error::NonLatin1(non_latin));
        }

        Ok(Latin1(s.to_string()))
    }
}

#[inline]
fn is_lower_latin(c: &char) -> bool {
    ('\u{20}'..'\u{7F}').contains(c)
}

#[inline]
fn is_upper_latin(c: &char) -> bool {
    ('\u{A0}'..'\u{0100}').contains(c)
}

#[inline]
fn is_latin(c: &char) -> bool {
    is_lower_latin(c) || is_upper_latin(c)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn lower_latin() {
        let lower_latin_chars = vec![
            ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0',
            '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A',
            'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
            'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c',
            'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~',
        ];
        assert!(lower_latin_chars.iter().all(is_lower_latin));
    }

    #[test]
    fn upper_latin() {
        let upper_latin_chars = vec![
            ' ', '¡', '¢', '£', '¤', '¥', '¦', '§', '¨', '©', 'ª', '«', '¬', '­', '®', '¯', '°',
            '±', '²', '³', '´', 'µ', '¶', '·', '¸', '¹', 'º', '»', '¼', '½', '¾', '¿', 'À', 'Á',
            'Â', 'Ã', 'Ä', 'Å', 'Æ', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Ð', 'Ñ', 'Ò',
            'Ó', 'Ô', 'Õ', 'Ö', '×', 'Ø', 'Ù', 'Ú', 'Û', 'Ü', 'Ý', 'Þ', 'ß', 'à', 'á', 'â', 'ã',
            'ä', 'å', 'æ', 'ç', 'è', 'é', 'ê', 'ë', 'ì', 'í', 'î', 'ï', 'ð', 'ñ', 'ò', 'ó', 'ô',
            'õ', 'ö', '÷', 'ø', 'ù', 'ú', 'û', 'ü', 'ý', 'þ', 'ÿ',
        ];
        assert!(upper_latin_chars.iter().all(is_upper_latin));
    }
}
