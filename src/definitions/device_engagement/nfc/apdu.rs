use strum_macros::EnumIter;

// This has been written according to ISO 7816-4 (2005).
// This only implements what is required for NFC handover to BLE.

use crate::definitions::device_engagement::nfc::{
    impl_partial_enum,
    util::{IntoRaw, KnownOrRaw},
};

pub struct Response {
    pub code: ResponseCode,
    pub payload: Vec<u8>,
}
impl From<Response> for Vec<u8> {
    fn from(response: Response) -> Self {
        let mut response_bytes = Vec::with_capacity(2 + response.payload.len());
        response_bytes.extend_from_slice(&response.payload);
        response_bytes.extend_from_slice(&response.code.to_bytes());
        response_bytes
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    Ok = 0x9000,
    IncorrectLength = 0x6700,
    IncorrectP1OrP2 = 0x6B00,
    ConditionsNotSatisfied = 0x6985,
    FileOrApplicationNotFound = 0x6A82,
    InstructionNotSupported = 0x6D00,
    Unspecified = 0x6F00,
}

impl ResponseCode {
    pub fn to_bytes(self) -> [u8; 2] {
        [(self as u16 >> 8) as u8, self as u16 as u8]
    }
}

impl From<ResponseCode> for Response {
    fn from(code: ResponseCode) -> Self {
        Response {
            code,
            payload: Vec::new(),
        }
    }
}

#[repr(u16)]
#[derive(Debug, EnumIter, Clone, Copy, PartialEq, Eq)]
pub enum FileId {
    CapabilityContainer = 0xE103,
    NdefFile = 0xE104,
}
impl_partial_enum!(FileId, u16);

#[allow(dead_code)]
#[derive(Debug)]
pub enum Apdu<'a> {
    SelectFile {
        occurrence: select::Occurrence,
        control_info: select::ControlInfo,
        file_id: KnownOrRaw<u16, FileId>,
    },
    SelectAid {
        occurrence: select::Occurrence,
        control_info: select::ControlInfo,
        aid: &'a [u8],
    },
    ReadBinary {
        slice: std::ops::Range<usize>,
    },
    UpdateBinary {
        offset: usize,
        data: &'a [u8],
    },
}

macro_rules! apdu_fail {
    ($code:expr) => {
        return Err(Response::from($code))
    };
}

pub mod select {
    use super::{Response, ResponseCode};

    #[repr(u8)]
    #[rustfmt::skip]
    #[derive(strum_macros::FromRepr, Debug, Clone, Copy)]
    pub enum Occurrence {
        FirstOrOnly = 0b0000,
        Last        = 0b0001,
        Next        = 0b0010,
        Prev        = 0b0011,
    }

    #[repr(u8)]
    #[rustfmt::skip]
    #[derive(strum_macros::FromRepr, Debug, Clone, Copy)]
    pub enum ControlInfo {
        FciTemplate = 0b0000,
        FcpTemplate = 0b0100,
        FmdTemplate = 0b1000,
        NoResponse  = 0b1100,
    }

    pub fn get_request_info(p2: u8) -> (Occurrence, ControlInfo) {
        let (occurrence, control_info) = (p2 & 0b0011, p2 & 0b1100);

        // Safety: These enums cover the entire possible bit range of the masked values.
        let occurrence = Occurrence::from_repr(occurrence).unwrap();
        let control_info = ControlInfo::from_repr(control_info).unwrap();

        (occurrence, control_info)
    }

    impl ControlInfo {
        pub fn get_payload(&self, _full_id: &[u8]) -> Result<Response, Response> {
            match *self {
                ControlInfo::NoResponse => Ok(ResponseCode::Ok.into()),
                // The initial 6f header can be omitted, and the name payload
                // can be omitted if the full ID is provided.
                // Since we only match on full ID, this means the entire payload is optional.
                ControlInfo::FciTemplate => Ok(ResponseCode::Ok.into()),
                _ => apdu_fail!(ResponseCode::InstructionNotSupported),
            }
        }
    }
}

impl<'a> Apdu<'a> {
    pub fn parse(command_bytes: &'a [u8]) -> Result<Self, Response> {
        if command_bytes.len() < 4 {
            apdu_fail!(ResponseCode::IncorrectLength);
        }

        let (cla, ins, p1, p2) = (
            command_bytes[0],
            command_bytes[1],
            command_bytes[2],
            command_bytes[3],
        );

        let (payload_len, l_c_len) = if command_bytes.len() > 4 {
            if command_bytes[4] == 0x00 && command_bytes.len() > 6 {
                // 3 byte L_c (first byte is 0x00)
                let payload_len_bytes = &command_bytes[5..7];
                (
                    u16::from_be_bytes([payload_len_bytes[0], payload_len_bytes[1]]),
                    3,
                )
            } else {
                (command_bytes[4] as u16, 1)
            }
        } else {
            (0, 0)
        };
        let (payload_len, l_c_len) = (payload_len as usize, l_c_len as usize);

        let command_remainder = &command_bytes[4 + l_c_len..];

        let mut response_len = 0;
        if command_remainder.len() > payload_len {
            if command_remainder.len() - payload_len != l_c_len {
                tracing::error!(
                    "Expected the remainder({}) after payload len({}) to be same as Lc len ({})",
                    command_remainder.len(),
                    payload_len,
                    l_c_len
                );
                apdu_fail!(ResponseCode::Unspecified);
            }
            let resp_bytes = &command_remainder[payload_len..];
            response_len = match l_c_len {
                1 => resp_bytes[0] as usize,
                3 => u16::from_be_bytes([resp_bytes[1], resp_bytes[2]]) as usize,
                _ => {
                    unreachable!()
                }
            }
        }

        tracing::debug!("Processing APDU command: CLA: {cla}, INS: {ins}, P1: {p1}, P2: {p2}, LC Len: {l_c_len}, Payload Length: {payload_len}, Resp len: {response_len}");

        let ins_bit1 = (ins & 0b0000_0001) != 0;
        let p1_bit8 = (p1 & 0b1000_0000) != 0;

        Ok(match (ins, p1, p2) {
            (0xA4, _, _) => {
                // Select §7.1.1
                let (occurrence, control_info) = select::get_request_info(p2);

                match p1 {
                    0x00 => {
                        // Select file
                        let file_id_raw = &command_remainder[..payload_len];
                        if file_id_raw.len() != 2 {
                            apdu_fail!(ResponseCode::IncorrectLength);
                        }
                        let file_id = u16::from_be_bytes([file_id_raw[0], file_id_raw[1]]).into();
                        Apdu::SelectFile {
                            occurrence,
                            control_info,
                            file_id,
                        }
                    }
                    0x04 => {
                        // Select AID
                        let aid = &command_remainder[..payload_len];
                        Apdu::SelectAid {
                            occurrence,
                            control_info,
                            aid,
                        }
                    }
                    _ => {
                        apdu_fail!(ResponseCode::InstructionNotSupported)
                    }
                }
            }
            (0xB0, _, _) => {
                // Read binary §7.2.3
                let response_len = payload_len;
                #[allow(unused)]
                let payload_len = (); // Shadow payload_len so it's not erroneously referenced.

                let offset;
                match (ins_bit1, p1_bit8) {
                    (false, true) => {
                        // We don't support P1 containing an EF identifier right now.
                        // See ISO 7816-4:2005 §7.2.2
                        apdu_fail!(ResponseCode::Unspecified)
                    }
                    (false, false) => {
                        offset = u16::from_be_bytes([p1, p2]) as usize;
                    }
                    _ => {
                        // We don't support P1 containing an EF identifier right now.
                        // Since this is a different instruction, we just return instruction unsupported.
                        apdu_fail!(ResponseCode::InstructionNotSupported)
                    }
                }

                Apdu::ReadBinary {
                    slice: offset..offset + response_len,
                }
            }
            (0xD6, _, _) => {
                // Update binary §7.2.5
                let offset;
                match (ins_bit1, p1_bit8) {
                    (false, true) => {
                        // We don't support P1 containing an EF identifier right now.
                        // See ISO 7816-4:2005 §7.2.2
                        apdu_fail!(ResponseCode::Unspecified)
                    }
                    (false, false) => {
                        offset = u16::from_be_bytes([p1, p2]) as usize;
                    }
                    _ => {
                        // We don't support P1 containing an EF identifier right now.
                        // Since this is a different instruction, we just return instruction unsupported.
                        apdu_fail!(ResponseCode::InstructionNotSupported)
                    }
                }
                Apdu::UpdateBinary {
                    offset,
                    data: &command_remainder[0..payload_len],
                }
            }
            _ => apdu_fail!(ResponseCode::InstructionNotSupported),
        })
    }
}
