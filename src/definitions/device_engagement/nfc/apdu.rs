use strum_macros::EnumIter;
use tracing::warn;

// This has been written according to ISO 7816-4 (2005).
// This only implements what is required for NFC handover to BLE.

use crate::definitions::device_engagement::nfc::{
    impl_partial_enum,
    util::{IntoRaw, KnownOrRaw},
};

#[derive(Debug)]
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
impl TryFrom<&[u8]> for Response {
    type Error = &'static str;
    fn try_from(response: &[u8]) -> Result<Self, Self::Error> {
        if response.len() < 2 {
            return Err("Response is not long enough");
        }
        let (payload, code) = response.split_last_chunk::<2>().unwrap();
        let code: ResponseCode = match u16::from_be_bytes(*code).try_into() {
            Ok(c) => c,
            Err(_) => return Err("Unknown response code: {code}"),
        };
        Ok(Self {
            code,
            payload: payload.to_vec(),
        })
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

impl TryFrom<u16> for ResponseCode {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x9000 => Ok(ResponseCode::Ok),
            0x6700 => Ok(ResponseCode::IncorrectLength),
            0x6B00 => Ok(ResponseCode::IncorrectP1OrP2),
            0x6985 => Ok(ResponseCode::ConditionsNotSatisfied),
            0x6A82 => Ok(ResponseCode::FileOrApplicationNotFound),
            0x6D00 => Ok(ResponseCode::InstructionNotSupported),
            0x6F00 => Ok(ResponseCode::Unspecified),
            _ => Err(()),
        }
    }
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

fn serialize_l_c_len(len: usize) -> Vec<u8> {
    if len < 256 {
        (len as u8).to_be_bytes().to_vec()
    } else {
        [&[0x00], (len as u16).to_be_bytes().as_slice()].concat()
    }
}

impl<'a> Apdu<'a> {
    pub fn parse(command_bytes: &'a [u8]) -> Result<Self, Response> {
        tracing::debug!("APDU: {command_bytes:?}");
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let cla = 0x00;

        let (ins, p1, p2, remainder) = match self {
            Apdu::SelectFile {
                occurrence,
                control_info,
                file_id,
            } => {
                let ins = 0xA4;
                let p1 = 0x00;
                let p2 = *control_info as u8 | *occurrence as u8;
                let payload = file_id.into_raw().to_be_bytes().to_vec();
                let payload_len = serialize_l_c_len(payload.len());
                let l_e_len = vec![]; // no restrictions on the response length
                let remainder = [payload_len, payload, l_e_len].concat();
                (ins, p1, p2, remainder)
            }
            Apdu::SelectAid {
                occurrence,
                control_info,
                aid,
            } => {
                let ins = 0xA4;
                let p1 = 0x04;
                let p2 = *control_info as u8 | *occurrence as u8;
                let payload_len = serialize_l_c_len(aid.len());
                let l_e_len = vec![0x00]; // a short response seems enough
                let remainder = [payload_len, aid.to_vec(), l_e_len].concat();
                (ins, p1, p2, remainder)
            }
            Apdu::ReadBinary { slice } => {
                let ins = 0xB0; // data is absent
                let p = (slice.start as u16).to_be_bytes();
                // assuming b8 of P1 will be 0 so the holder knows the two bytes are one number
                // (see 7.2.2 of ISO 7816-4)
                let p1 = p[0];
                if p1 > 127 {
                    warn!("P1 has b8 with a value of 1 which might impact the ReadBinary instruction's interpretation");
                }
                let p2 = p[1];
                let payload_len = (slice.len() as u8).to_be_bytes().to_vec();
                let remainder = payload_len;
                (ins, p1, p2, remainder)
            }
            Apdu::UpdateBinary { offset, data } => {
                let ins = 0xD6; // string of data
                let p = (*offset as u16).to_be_bytes();
                // assuming b8 of P1 will be 0 so the holder knows the two bytes are one number
                // (see 7.2.2 of ISO 7816-4)
                let p1 = p[0];
                if p1 > 127 {
                    warn!("P1 has b8 with a value of 1 which might impact the UpdateBinary instruction's interpretation");
                }
                let p2 = p[1];
                let payload_len = serialize_l_c_len(data.len());
                let remainder = [payload_len, data.to_vec()].concat();
                (ins, p1, p2, remainder)
            }
        };
        [vec![cla, ins, p1, p2], remainder].concat()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_apdus(apdus: Vec<Vec<u8>>) {
        for apdu in apdus {
            let parsed_apdu = Apdu::parse(&apdu).expect("Failed to parse APDU");
            println!("APDU: {parsed_apdu:?}");
            assert_eq!(apdu, parsed_apdu.to_bytes());
        }
    }

    #[test]
    /// real APDUs from the GET verifier app
    fn get_apdus() {
        let apdus = vec![
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x48, 0x04, 0x00, 0x00,
            ],
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03],
            vec![0x00, 0xB0, 0x00, 0x00, 0x0F],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03],
            vec![0x00, 0xB0, 0x00, 0x00, 0x0F],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x02, 0xCC],
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03],
            vec![0x00, 0xB0, 0x00, 0x00, 0x0F],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x02, 0xCC],
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03],
            vec![0x00, 0xB0, 0x00, 0x00, 0x0F],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x02, 0xCC],
        ];
        test_apdus(apdus);
    }

    #[test]
    /// real APDUs from the Idemia verifier app
    fn idemia_apdus() {
        let apdus = vec![
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03],
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03],
            vec![0x00, 0xB0, 0x00, 0x00, 0x0F],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x02, 0xCC],
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03],
            vec![0x00, 0xB0, 0x00, 0x00, 0x0F],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x02, 0xCC],
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
            ],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03],
            vec![0x00, 0xB0, 0x00, 0x00, 0x0F],
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x00, 0x02],
            vec![0x00, 0xB0, 0x00, 0x02, 0xCC],
        ];
        test_apdus(apdus);
    }

    #[test]
    /// test APDUs from multipaz
    /// https://github.com/openwallet-foundation/multipaz/blob/96b82c9ff7a34d18a67f09473e51200a202bee48/multipaz/src/commonTest/kotlin/org/multipaz/mdoc/nfc/MdocNfcEngagementHelperTest.kt#L10
    fn multipaz_tests_apdus() {
        let apdus = vec![
            // static
            // multipaz does not append Le when it's 0, the trailing 00 was added manually
            hex::decode("00a4040007d276000085010100").unwrap(),
            hex::decode("00a4000c02e103").unwrap(),
            hex::decode("00b000000f").unwrap(),
            hex::decode("00a4000c02e104").unwrap(),
            hex::decode("00b0000002").unwrap(),
            hex::decode("00b00002fe").unwrap(),
            // negotiated
            // multipaz does not append Le when it's 0, the trailing 00 was added manually
            hex::decode("00a4040007d276000085010100").unwrap(),
            hex::decode("00a4000c02e103").unwrap(),
            hex::decode("00b000000f").unwrap(),
            hex::decode("00a4000c02e104").unwrap(),
            hex::decode("00b0000002").unwrap(),
            hex::decode("00b000021f").unwrap(),
            hex::decode("00d600001b0019d1021454731375726e3a6e66633a736e3a68616e646f766572").unwrap(),
            hex::decode("00b0000002").unwrap(),
            hex::decode("00b0000206").unwrap(),
            hex::decode("00d60000aa00a8910215487215910204616301013000510206616301036e6663001c1e060a69736f2e6f72673a31383031333a726561646572656e676167656d656e746d646f63726561646572a10063312e301a2015016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230021c031107b66eef55ee782ea2514bb6a1c42ad5b35c110a0369736f2e6f72673a31383031333a6e66636e6663010301ffff0402010000").unwrap(),
            hex::decode("00b0000002").unwrap(),
            hex::decode("00b00002ba").unwrap(),
        ];
        test_apdus(apdus);
    }
}
