use crate::cbor::CborValue;
use crate::definitions::device_engagement::error::Error;
use anyhow::Result;
use ciborium::Value;
use coset::AsCborValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The maximum length of the NFC command, as specified in ISO_18013-5 2021 Section 8.3.3.1.2
/// Values of this type must lie between 255 and 65,535 inclusive, as specified in Note 2.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandDataLength(u16);

/// The maximum length of the NFC response data, as specified in ISO_18013-5 2021 Section 8.3.3.1.2
/// Values of this type must lie between 256 and 65,536 inclusive, as specified in Note 2.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseDataLength(u32);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NfcOptions {
    max_len_command_data_field: CommandDataLength,
    max_len_response_data_field: ResponseDataLength,
}

impl coset::CborSerializable for NfcOptions {}
impl AsCborValue for NfcOptions {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let cbor = CborValue::from(value);
        Ok(cbor.try_into().map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "invalid bytes".to_string(),
            ))
        })?)
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let cbor: CborValue = self
            .try_into()
            .map_err(|_| coset::CoseError::EncodeFailed)?;
        Ok(cbor.into())
    }
}

impl TryFrom<CborValue> for NfcOptions {
    type Error = Error;

    fn try_from(v: CborValue) -> Result<Self, Error> {
        let map: BTreeMap<CborValue, CborValue> = match v.into() {
            ciborium::Value::Map(map) => Ok(map
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect::<BTreeMap<_, _>>()),
            _ => Err(Error::InvalidNfcOptions),
        }?;

        Ok(NfcOptions::default())
            .and_then(|nfc_opts| {
                map.get(&Value::Integer(0.into()).into())
                    .ok_or(Error::InvalidNfcOptions)
                    .and_then(CommandDataLength::try_from)
                    .map(|max_len_command_data_field| NfcOptions {
                        max_len_command_data_field,
                        ..nfc_opts
                    })
            })
            .and_then(|nfc_opts| {
                map.get(&Value::Integer(1.into()).into())
                    .ok_or(Error::InvalidNfcOptions)
                    .and_then(ResponseDataLength::try_from)
                    .map(|max_len_response_data_field| NfcOptions {
                        max_len_response_data_field,
                        ..nfc_opts
                    })
            })
    }
}

impl From<NfcOptions> for CborValue {
    fn from(o: NfcOptions) -> CborValue {
        let mut map = vec![];
        map.push((
            Value::Integer(0.into()).into(),
            Value::Integer(o.max_len_command_data_field.get().into()),
        ));
        map.push((
            Value::Integer(1.into()).into(),
            Value::Integer(o.max_len_response_data_field.get().into()),
        ));

        Value::Map(map).into()
    }
}

impl CommandDataLength {
    pub const MIN: CommandDataLength = CommandDataLength(255);
    pub const MAX: CommandDataLength = CommandDataLength(65535);

    pub const fn new(v: u16) -> Option<CommandDataLength> {
        match v >= Self::MIN.get() && v <= Self::MAX.get() {
            true => Some(CommandDataLength(v)),
            false => None,
        }
    }

    pub const fn get(&self) -> u16 {
        self.0
    }
}

/// ISO_18013-5 2021 does not specify a default value for the Command Data Length, so we make
/// a safe assumption here and specify the minimum value, which is 255.
impl Default for CommandDataLength {
    fn default() -> Self {
        Self::MIN
    }
}

macro_rules! command_data_length_try_from {
    ( $( $Ty: ident($Int: ty); )+ ) => {
        $(
            impl TryFrom<$Int> for $Ty {
                type Error = Error;

                fn try_from(v: $Int) -> Result<Self, Self::Error> {
                    u16::try_from(v)
                        .ok()
                        .and_then(|uv| CommandDataLength::new(uv))
                        .ok_or(Error::InvalidNfcCommandDataLengthError)
                }
            }
        )+
    }
}

command_data_length_try_from! {
    CommandDataLength(i32);
    CommandDataLength(i64);
    CommandDataLength(i128);
    CommandDataLength(u16);
    CommandDataLength(u32);
    CommandDataLength(u64);
    CommandDataLength(u128);
    CommandDataLength(isize);
    CommandDataLength(usize);
}

impl TryFrom<&CborValue> for CommandDataLength {
    type Error = Error;

    fn try_from(v: &CborValue) -> Result<Self, Error> {
        let v: Value = v.clone().into();
        match v {
            Value::Integer(int_val) => {
                let int_val: u64 = int_val
                    .try_into()
                    .map_err(|_| Error::InvalidNfcCommandDataLengthError)?;
                Self::try_from(int_val)
            }
            _ => Err(Error::InvalidNfcOptions),
        }
    }
}

impl From<CommandDataLength> for CborValue {
    fn from(cdl: CommandDataLength) -> CborValue {
        Value::Integer(cdl.get().into()).into()
    }
}

impl ResponseDataLength {
    pub const MIN: ResponseDataLength = ResponseDataLength(256);
    pub const MAX: ResponseDataLength = ResponseDataLength(65536);

    pub fn new(v: u32) -> Option<ResponseDataLength> {
        match v >= Self::MIN.get() && v <= Self::MAX.get() {
            true => Some(ResponseDataLength(v)),
            false => None,
        }
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}

/// ISO_18013-5 2021 does not specify a default value for the Response Data Length, so we make
/// a safe assumption here and specify the minimum value, which is 256.
impl Default for ResponseDataLength {
    fn default() -> Self {
        Self::MIN
    }
}

macro_rules! response_data_length_try_from {
    ( $( $Ty: ident($Int: ty); )+ ) => {
        $(
            impl TryFrom<$Int> for $Ty {
                type Error = Error;

                fn try_from(v: $Int) -> Result<Self, Self::Error> {
                    u32::try_from(v)
                        .ok()
                        .and_then(|uv| ResponseDataLength::new(uv))
                        .ok_or(Error::InvalidNfcResponseDataLengthError)
                }
            }
        )+
    }
}

response_data_length_try_from! {
    ResponseDataLength(i64);
    ResponseDataLength(i128);
    ResponseDataLength(u32);
    ResponseDataLength(u64);
    ResponseDataLength(u128);
    ResponseDataLength(isize);
    ResponseDataLength(usize);
}

impl TryFrom<&CborValue> for ResponseDataLength {
    type Error = Error;

    fn try_from(v: &CborValue) -> Result<Self, Error> {
        let v: Value = v.clone().into();
        match v {
            Value::Integer(int_val) => {
                let int_val: u64 = int_val
                    .try_into()
                    .map_err(|_| Error::InvalidNfcResponseDataLengthError)?;
                Self::try_from(int_val)
            }
            _ => Err(Error::InvalidNfcOptions),
        }
    }
}

impl From<ResponseDataLength> for CborValue {
    fn from(rdl: ResponseDataLength) -> CborValue {
        ciborium::Value::Integer(rdl.get().into()).into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn command_data_length_valid_data_test() {
        let v: u16 = 342;
        assert_eq!(Some(CommandDataLength(v)), CommandDataLength::new(v));
    }

    #[test]
    fn command_data_length_too_small_test() {
        let v: u16 = 0;
        assert_eq!(None, CommandDataLength::new(v));
    }

    #[test]
    fn command_data_length_wrong_type_test() {
        let v: u16 = 2345;
        let v64: i64 = v.into();

        assert_eq!(
            Some(CommandDataLength(v)),
            CommandDataLength::new(v64.try_into().unwrap())
        );
    }

    #[test]
    fn command_data_literal_test() {
        assert_eq!(Some(CommandDataLength(2345)), CommandDataLength::new(2345));
    }

    #[test]
    fn command_data_try_from_i32_test() {
        let u16v: u16 = 2345;
        let i32v: i32 = u16v.into();
        assert_eq!(
            Ok(CommandDataLength(u16v)),
            CommandDataLength::try_from(i32v)
        );
    }

    #[test]
    fn command_data_try_from_u64_test() {
        let u16v: u16 = 2345;
        let u64v: u64 = u16v.into();
        assert_eq!(
            Ok(CommandDataLength(u16v)),
            CommandDataLength::try_from(u64v)
        );
    }

    #[test]
    fn command_data_try_from_u64_fails_test() {
        let u64v: u64 = u64::MAX;
        assert_eq!(
            Err(Error::InvalidNfcCommandDataLengthError),
            CommandDataLength::try_from(u64v)
        );
    }

    #[test]
    fn command_data_length_cbor_roundtrip_test() {
        let cdl: CommandDataLength = CommandDataLength::new(512).unwrap();
        let bytes: Vec<u8> = serde_cbor::to_vec(&cdl).unwrap();
        let deserialized: CommandDataLength = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(cdl, deserialized);
    }

    #[test]
    fn response_data_length_valid_data_test() {
        let v: u32 = 342;
        assert_eq!(Some(ResponseDataLength(v)), ResponseDataLength::new(v));
    }

    #[test]
    fn response_data_length_too_small_test() {
        let v: u32 = 0;
        assert_eq!(None, ResponseDataLength::new(v));
    }

    #[test]
    fn response_data_length_wrong_type_test() {
        let v: u32 = 2345;
        let v64: i64 = v.into();

        assert_eq!(
            Some(ResponseDataLength(v)),
            ResponseDataLength::new(v64.try_into().unwrap())
        );
    }

    #[test]
    fn response_data_literal_test() {
        assert_eq!(
            Some(ResponseDataLength(2345)),
            ResponseDataLength::new(2345)
        );
    }

    #[test]
    fn response_data_try_from_i64_test() {
        let u32v: u32 = 2345;
        let i64v: i64 = u32v.into();
        assert_eq!(
            Ok(ResponseDataLength(u32v)),
            ResponseDataLength::try_from(i64v)
        );
    }

    #[test]
    fn response_data_try_from_u64_test() {
        let u32v: u32 = 2345;
        let u64v: u64 = u32v.into();
        assert_eq!(
            Ok(ResponseDataLength(u32v)),
            ResponseDataLength::try_from(u64v)
        );
    }

    #[test]
    fn response_data_try_from_u64_fails_test() {
        let u64v: u64 = u64::MAX;
        assert_eq!(
            Err(Error::InvalidNfcResponseDataLengthError),
            ResponseDataLength::try_from(u64v)
        );
    }

    #[test]
    fn response_data_length_cbor_roundtrip_test() {
        let rdl: ResponseDataLength = ResponseDataLength::new(512).unwrap();
        let bytes: Vec<u8> = serde_cbor::to_vec(&rdl).unwrap();
        let deserialized: ResponseDataLength = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(rdl, deserialized);
    }

    fn nfc_options_cbor_roundtrip_test(nfc_options: NfcOptions) {
        let bytes: Vec<u8> = serde_cbor::to_vec(&nfc_options).unwrap();
        let deserialized: NfcOptions = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(nfc_options, deserialized);
    }

    #[test]
    fn nfc_options_cbor_roundtrip_min_command_data() {
        let nfc_options: NfcOptions = NfcOptions {
            max_len_command_data_field: CommandDataLength::MIN,
            max_len_response_data_field: ResponseDataLength::new(1024).unwrap(),
        };

        nfc_options_cbor_roundtrip_test(nfc_options);
    }

    #[test]
    fn nfc_options_cbor_roundtrip_min_response_data() {
        let nfc_options: NfcOptions = NfcOptions {
            max_len_command_data_field: CommandDataLength::new(4096).unwrap(),
            max_len_response_data_field: ResponseDataLength::MIN,
        };

        nfc_options_cbor_roundtrip_test(nfc_options);
    }

    #[test]
    fn nfc_options_cbor_roundtrip_command_length_error_test() {
        let nfc_options: NfcOptions = NfcOptions {
            max_len_command_data_field: CommandDataLength(0), //This should not work in non-tests
            max_len_response_data_field: ResponseDataLength::MIN,
        };

        let bytes: Vec<u8> = serde_cbor::to_vec(&nfc_options).unwrap();
        let deserialized_result: Result<NfcOptions, Error> =
            serde_cbor::from_slice(&bytes).map_err(Error::from);
        assert_eq!(Err(Error::SerdeCborError), deserialized_result);
    }

    #[test]
    fn nfc_options_cbor_roundtrip_response_data_error_test() {
        let nfc_options: NfcOptions = NfcOptions {
            max_len_command_data_field: CommandDataLength(0), //This should not work in non-tests
            max_len_response_data_field: ResponseDataLength::MIN,
        };

        let bytes: Vec<u8> = serde_cbor::to_vec(&nfc_options).unwrap();
        let deserialized_result: Result<NfcOptions, Error> =
            serde_cbor::from_slice(&bytes).map_err(Error::from);
        assert_eq!(Err(Error::SerdeCborError), deserialized_result);
    }
}
