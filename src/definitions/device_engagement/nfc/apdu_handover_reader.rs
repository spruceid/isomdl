use crate::definitions::device_engagement::nfc::{
    apdu::{
        self,
        select::{ControlInfo, Occurrence},
        Apdu, FileId,
    },
    ndef_handover::TNEP_HANDOVER_SERVICE_URI,
    ndef_handover_reader::{
        detect_tp_service, generate_hr_ndef, generate_ts_ndef, parse_te_ndef, ReaderHandoverState,
        ReaderNegotiatedCarrierInfo,
    },
    util::KnownOrRaw,
    APDU_AID_NDEF_APPLICATION, CC_FILE_TEMPLATE,
};

use crate::definitions::helpers::ByteStr;
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum ReaderApduError {
    #[error("CC File is of invalid length: {0} instead of {1}")]
    CCFileInvalidLength(usize, usize),
    #[error("CC File has invalid file ID: {0} instead of {1}")]
    CCFileInvalidFileId(u16, u16),
    #[error("Handover is done")]
    Done,
    #[error("Invalid APDU response: {0}")]
    InvalidApduResponse(String),
    #[error("APDU response indicates a failure: {0}")]
    NegativeApduResponse(String),
    #[error("NDEF decoding failure: {0}")]
    NdefMessageError(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct ReaderApduHandoverDriver {
    state: ReaderHandoverState,
    /// Maximum amount of bytes in an APDU command or response. Used to be able to transmit large
    /// amount of data in multiple chunks.
    max_buffer_size: usize,
}

#[derive(Debug, Clone)]
pub enum ReaderApduProgress {
    InProgress(Vec<u8>),
    Done(Box<ReaderNegotiatedCarrierInfo>),
}

fn with_ndef_length_prefix(ndef: &[u8]) -> Vec<u8> {
    let len_bytes = (ndef.len() as u16).to_be_bytes();
    [len_bytes.as_slice(), ndef].concat()
}

impl ReaderApduHandoverDriver {
    /// Create a new APDU handover driver.
    pub fn new() -> (Self, Vec<u8>) {
        let self_ = Self {
            state: ReaderHandoverState::WaitingForAidResponse,
            // hardcoding the buffer size to the standard short APDU limit for now, but in the
            // future we might have to make it configurable if we see either the need to use
            // extended APDUs or encounter discrepancies between platforms.
            max_buffer_size: 264,
        };
        let apdu = Apdu::SelectAid {
            occurrence: Occurrence::FirstOrOnly,
            control_info: ControlInfo::FciTemplate,
            aid: APDU_AID_NDEF_APPLICATION,
        };
        (self_, apdu.to_bytes())
    }

    pub fn process_rapdu(&mut self, rapdu: &[u8]) -> Result<ReaderApduProgress, ReaderApduError> {
        let rapdu = match apdu::Response::try_from(rapdu) {
            Ok(r) => r,
            Err(e) => return Err(ReaderApduError::InvalidApduResponse(e.into())),
        };
        debug!("Received response APDU: {rapdu:?}");
        if rapdu.code != apdu::ResponseCode::Ok {
            return Err(ReaderApduError::NegativeApduResponse(format!(
                "{:?}",
                rapdu.code
            )));
        }
        match &self.state {
            ReaderHandoverState::WaitingForAidResponse => {
                self.state = ReaderHandoverState::WaitingForCapabilitiesFileResponse;
                let apdu = Apdu::SelectFile {
                    occurrence: Occurrence::FirstOrOnly,
                    control_info: ControlInfo::NoResponse,
                    file_id: KnownOrRaw::Known(FileId::CapabilityContainer),
                };
                Ok(ReaderApduProgress::InProgress(apdu.to_bytes()))
            }
            ReaderHandoverState::WaitingForCapabilitiesFileResponse => {
                self.state = ReaderHandoverState::WaitingForCapabilitiesReadResponse;
                let apdu = Apdu::ReadBinary {
                    slice: 0..CC_FILE_TEMPLATE.len(),
                };
                Ok(ReaderApduProgress::InProgress(apdu.to_bytes()))
            }
            ReaderHandoverState::WaitingForCapabilitiesReadResponse => {
                self.state = ReaderHandoverState::WaitingForNdefFileResponse;
                let ndef_recv = rapdu.payload;
                let ndef_recv_len = ndef_recv.len();
                if ndef_recv_len != CC_FILE_TEMPLATE.len() {
                    return Err(ReaderApduError::CCFileInvalidLength(
                        ndef_recv_len,
                        CC_FILE_TEMPLATE.len(),
                    ));
                }
                let ndef_recv_fileid = u16::from_be_bytes([ndef_recv[9], ndef_recv[10]]);
                if ndef_recv_fileid != FileId::NdefFile as u16 {
                    return Err(ReaderApduError::CCFileInvalidFileId(
                        ndef_recv_fileid,
                        FileId::NdefFile as u16,
                    ));
                }
                let apdu = Apdu::SelectFile {
                    occurrence: Occurrence::FirstOrOnly,
                    control_info: ControlInfo::NoResponse,
                    file_id: KnownOrRaw::Known(FileId::NdefFile),
                };
                Ok(ReaderApduProgress::InProgress(apdu.to_bytes()))
            }
            ReaderHandoverState::WaitingForNdefFileResponse => {
                self.state = ReaderHandoverState::WaitingForNdefReadResponseLength;
                let apdu = Apdu::ReadBinary { slice: 0..2 };
                Ok(ReaderApduProgress::InProgress(apdu.to_bytes()))
            }
            ReaderHandoverState::WaitingForNdefReadResponseLength => {
                let ndef_recv = rapdu.payload;
                if ndef_recv.len() != 2 {
                    return Err(ReaderApduError::InvalidApduResponse("Expected to receive length indication, but payload doesn't have a payload of 2 bytes".into()));
                }
                let ndef_len = u16::from_be_bytes(*ndef_recv.first_chunk::<2>().unwrap()) as usize;
                let chunk_len = if ndef_len <= self.max_buffer_size {
                    ndef_len
                } else {
                    self.max_buffer_size
                };
                let apdu = Apdu::ReadBinary {
                    slice: 2..2 + chunk_len,
                };
                self.state = ReaderHandoverState::WaitingForNdefReadResponseData {
                    total_length: ndef_len,
                    data: vec![],
                };
                Ok(ReaderApduProgress::InProgress(apdu.to_bytes()))
            }
            ReaderHandoverState::WaitingForNdefReadResponseData { total_length, data } => {
                let ndef_recv = rapdu.payload;
                let data = [data, ndef_recv.as_slice()].concat();
                let offset = data.len();
                if &offset == total_length {
                    if detect_tp_service(&data).is_some() {
                        // Negotiated handover: write Ts (Service Select)
                        let ts_ndef = generate_ts_ndef(TNEP_HANDOVER_SERVICE_URI)
                            .map_err(ReaderApduError::NdefMessageError)?;
                        let ts_apdu = Apdu::UpdateBinary {
                            offset: 0,
                            data: &with_ndef_length_prefix(&ts_ndef),
                        };
                        self.state = ReaderHandoverState::WaitingForTsWriteResponse;
                        Ok(ReaderApduProgress::InProgress(ts_apdu.to_bytes()))
                    } else {
                        // Static handover
                        let carrier_info = ReaderNegotiatedCarrierInfo::parse_ndef_message(&data)
                            .map_err(ReaderApduError::NdefMessageError)?;
                        self.state = ReaderHandoverState::Done;
                        Ok(ReaderApduProgress::Done(Box::new(carrier_info)))
                    }
                } else {
                    let chunk_len = if total_length - offset <= self.max_buffer_size {
                        total_length - offset
                    } else {
                        self.max_buffer_size
                    };
                    let apdu = Apdu::ReadBinary {
                        slice: offset..offset + chunk_len,
                    };
                    self.state = ReaderHandoverState::WaitingForNdefReadResponseData {
                        total_length: *total_length,
                        data,
                    };
                    Ok(ReaderApduProgress::InProgress(apdu.to_bytes()))
                }
            }
            // Negotiated handover states
            ReaderHandoverState::WaitingForTsWriteResponse => {
                // Ts was written (0x9000 received); read the Te NDEF length
                self.state = ReaderHandoverState::WaitingForTeLength;
                Ok(ReaderApduProgress::InProgress(
                    Apdu::ReadBinary { slice: 0..2 }.to_bytes(),
                ))
            }
            ReaderHandoverState::WaitingForTeLength => {
                let te_len_bytes = rapdu.payload;
                if te_len_bytes.len() != 2 {
                    return Err(ReaderApduError::InvalidApduResponse(
                        "Expected 2-byte Te NDEF length".into(),
                    ));
                }
                let te_len = u16::from_be_bytes([te_len_bytes[0], te_len_bytes[1]]) as usize;
                let chunk_len = te_len.min(self.max_buffer_size);
                self.state = ReaderHandoverState::WaitingForTeData {
                    total_length: te_len,
                    data: vec![],
                };
                Ok(ReaderApduProgress::InProgress(
                    Apdu::ReadBinary {
                        slice: 2..2 + chunk_len,
                    }
                    .to_bytes(),
                ))
            }
            ReaderHandoverState::WaitingForTeData { total_length, data } => {
                let data = [data, rapdu.payload.as_slice()].concat();
                let offset = data.len();
                if &offset == total_length {
                    // Te received; check TNEP status then write Hr
                    parse_te_ndef(&data).map_err(ReaderApduError::NdefMessageError)?;
                    let (hr_ndef, hr_uuid) =
                        generate_hr_ndef().map_err(ReaderApduError::NdefMessageError)?;
                    let hr_bytes = hr_ndef.clone();
                    let hr_apdu = Apdu::UpdateBinary {
                        offset: 0,
                        data: &with_ndef_length_prefix(&hr_ndef),
                    };
                    self.state =
                        ReaderHandoverState::WaitingForHrWriteResponse { hr_bytes, hr_uuid };
                    Ok(ReaderApduProgress::InProgress(hr_apdu.to_bytes()))
                } else {
                    let chunk_len = (total_length - offset).min(self.max_buffer_size);
                    self.state = ReaderHandoverState::WaitingForTeData {
                        total_length: *total_length,
                        data,
                    };
                    Ok(ReaderApduProgress::InProgress(
                        Apdu::ReadBinary {
                            slice: 2 + offset..2 + offset + chunk_len,
                        }
                        .to_bytes(),
                    ))
                }
            }
            ReaderHandoverState::WaitingForHrWriteResponse { hr_bytes, hr_uuid } => {
                // Hr was written (0x9000 received); read the Hs NDEF length
                let hr_bytes = hr_bytes.clone();
                let hr_uuid = *hr_uuid;
                self.state = ReaderHandoverState::WaitingForHsLength { hr_bytes, hr_uuid };
                Ok(ReaderApduProgress::InProgress(
                    Apdu::ReadBinary { slice: 0..2 }.to_bytes(),
                ))
            }
            ReaderHandoverState::WaitingForHsLength { hr_bytes, hr_uuid } => {
                let hs_len_bytes = rapdu.payload;
                if hs_len_bytes.len() != 2 {
                    return Err(ReaderApduError::InvalidApduResponse(
                        "Expected 2-byte Hs NDEF length".into(),
                    ));
                }
                let hs_len = u16::from_be_bytes([hs_len_bytes[0], hs_len_bytes[1]]) as usize;
                let chunk_len = hs_len.min(self.max_buffer_size);
                let hr_bytes = hr_bytes.clone();
                let hr_uuid = *hr_uuid;
                self.state = ReaderHandoverState::WaitingForHsData {
                    total_length: hs_len,
                    data: vec![],
                    hr_bytes,
                    hr_uuid,
                };
                Ok(ReaderApduProgress::InProgress(
                    Apdu::ReadBinary {
                        slice: 2..2 + chunk_len,
                    }
                    .to_bytes(),
                ))
            }
            ReaderHandoverState::WaitingForHsData {
                total_length,
                data,
                hr_bytes,
                hr_uuid,
            } => {
                let data = [data, rapdu.payload.as_slice()].concat();
                let offset = data.len();
                if &offset == total_length {
                    let mut carrier_info =
                        ReaderNegotiatedCarrierInfo::parse_hs_ndef_message(&data, *hr_uuid)
                            .map_err(ReaderApduError::NdefMessageError)?;
                    carrier_info.hr_message = Some(ByteStr::from(hr_bytes.clone()));
                    self.state = ReaderHandoverState::Done;
                    Ok(ReaderApduProgress::Done(Box::new(carrier_info)))
                } else {
                    let chunk_len = (total_length - offset).min(self.max_buffer_size);
                    let hr_bytes = hr_bytes.clone();
                    let hr_uuid = *hr_uuid;
                    self.state = ReaderHandoverState::WaitingForHsData {
                        total_length: *total_length,
                        data,
                        hr_bytes,
                        hr_uuid,
                    };
                    Ok(ReaderApduProgress::InProgress(
                        Apdu::ReadBinary {
                            slice: 2 + offset..2 + offset + chunk_len,
                        }
                        .to_bytes(),
                    ))
                }
            }
            ReaderHandoverState::Done => Err(ReaderApduError::Done),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// Transcript from a manual test
    fn multipaz_static() {
        let mut driver = ReaderApduHandoverDriver::new().0;
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 1");
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 2");
        driver
            .process_rapdu(&[
                0x00, 0x0F, 0x20, 0x7F, 0xFF, 0x7F, 0xFF, 0x04, 0x06, 0xE1, 0x04, 0x7F, 0xFF, 0x00,
                0xFF, 0x90, 0x00,
            ])
            .expect("failed to process rapdu 3");
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 4");
        driver
            .process_rapdu(&[0x00, 0xCC, 0x90, 0x00])
            .expect("failed to process rapdu 5");
        let res = driver
            .process_rapdu(&[
                0x91, 0x02, 0x0F, 0x48, 0x73, 0x15, 0xD1, 0x02, 0x09, 0x61, 0x63, 0x01, 0x01, 0x30,
                0x01, 0x04, 0x6D, 0x64, 0x6F, 0x63, 0x1C, 0x1E, 0x58, 0x04, 0x69, 0x73, 0x6F, 0x2E,
                0x6F, 0x72, 0x67, 0x3A, 0x31, 0x38, 0x30, 0x31, 0x33, 0x3A, 0x64, 0x65, 0x76, 0x69,
                0x63, 0x65, 0x65, 0x6E, 0x67, 0x61, 0x67, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x6D, 0x64,
                0x6F, 0x63, 0xA2, 0x00, 0x63, 0x31, 0x2E, 0x30, 0x01, 0x82, 0x01, 0xD8, 0x18, 0x58,
                0x4B, 0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, 0x81, 0x2E, 0x9E, 0xFE, 0x35,
                0x39, 0x5A, 0x9F, 0x66, 0x9A, 0x74, 0x3F, 0x1B, 0x26, 0xD1, 0x3F, 0xC4, 0xDF, 0xD7,
                0xA5, 0xBE, 0xCC, 0x84, 0x8F, 0xB6, 0xEA, 0x0B, 0x6E, 0xE8, 0xDC, 0x6C, 0xC7, 0x22,
                0x58, 0x20, 0x20, 0x91, 0x27, 0x55, 0xA4, 0x36, 0xB0, 0xAC, 0xC4, 0x4D, 0xEF, 0xB0,
                0x7C, 0x06, 0x76, 0xB9, 0x27, 0x4F, 0x6D, 0xF7, 0x24, 0x6D, 0x16, 0x27, 0xF9, 0x1E,
                0x8A, 0xDF, 0xAA, 0x43, 0x5A, 0xCB, 0x5A, 0x20, 0x15, 0x01, 0x61, 0x70, 0x70, 0x6C,
                0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 0x62, 0x6C,
                0x75, 0x65, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x2E, 0x6C, 0x65, 0x2E, 0x6F, 0x6F, 0x62,
                0x30, 0x02, 0x1C, 0x01, 0x11, 0x07, 0x43, 0xBC, 0x2A, 0x67, 0xBF, 0x79, 0x7A, 0xB0,
                0x40, 0x4D, 0xA0, 0x9E, 0x0E, 0x2E, 0x81, 0xE0, 0x90, 0x00,
            ])
            .expect("failed to process rapdu 6");
        assert!(matches!(res, ReaderApduProgress::Done(_)));
    }

    /// Full round-trip transcript from a manual test session with multipaz on Android.
    /// multipaz's Hs BLE OOB record contains only the LE Role (no UUID); the reader's Hr UUID
    /// is used as the fallback for the BLE connection.
    #[test_log::test]
    fn multipaz_negotiated() {
        let mut driver = ReaderApduHandoverDriver::new().0;
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 1");
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 2");
        driver
            .process_rapdu(&[
                0x00, 0x0F, 0x20, 0x7F, 0xFF, 0x7F, 0xFF, 0x04, 0x06, 0xE1, 0x04, 0x7F, 0xFF, 0x00,
                0x00, 0x90, 0x00,
            ])
            .expect("failed to process rapdu 3");
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 4");
        driver
            .process_rapdu(&[0x00, 0x1F, 0x90, 0x00])
            .expect("failed to process rapdu 5");
        // Device returns Tp (TNEP Service Parameter) record
        let res = driver
            .process_rapdu(&[
                0xD1, 0x02, 0x1A, 0x54, 0x70, 0x10, 0x13, 0x75, 0x72, 0x6E, 0x3A, 0x6E, 0x66, 0x63,
                0x3A, 0x73, 0x6E, 0x3A, 0x68, 0x61, 0x6E, 0x64, 0x6F, 0x76, 0x65, 0x72, 0x00, 0x00,
                0x0F, 0xFF, 0xFF, 0x90, 0x00,
            ])
            .expect("failed to process rapdu 6");
        // Driver should respond with UPDATE BINARY writing Ts (Service Select)
        let expected_ts_apdu =
            hex::decode("00d600001b0019d1021454731375726e3a6e66633a736e3a68616e646f766572")
                .unwrap();
        match res {
            ReaderApduProgress::InProgress(bytes) => assert_eq!(bytes, expected_ts_apdu),
            _ => panic!("expected InProgress with Ts UPDATE BINARY, got {res:?}"),
        }
        // Ts write acknowledged → READ BINARY 0..2 (Te length)
        let res = driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 7");
        match res {
            ReaderApduProgress::InProgress(bytes) => {
                assert_eq!(bytes, [0x00, 0xB0, 0x00, 0x00, 0x02]);
            }
            _ => panic!("expected READ BINARY for Te length, got {res:?}"),
        }
        // Te NDEF length = 6 bytes → READ BINARY 2..8 (Te data)
        let res = driver
            .process_rapdu(&[0x00, 0x06, 0x90, 0x00])
            .expect("failed to process rapdu 8");
        match res {
            ReaderApduProgress::InProgress(bytes) => {
                assert_eq!(bytes, [0x00, 0xB0, 0x00, 0x02, 0x06]);
            }
            _ => panic!("expected READ BINARY for Te data, got {res:?}"),
        }
        // Te data (TNEP status 0x00 = success) → UPDATE BINARY Hr (171 bytes)
        let res = driver
            .process_rapdu(&[0xD1, 0x02, 0x01, 0x54, 0x65, 0x00, 0x90, 0x00])
            .expect("failed to process rapdu 9");
        let ReaderApduProgress::InProgress(hr_apdu) = res else {
            panic!("expected InProgress with Hr UPDATE BINARY, got {res:?}");
        };
        assert_eq!(hr_apdu.len(), 171);
        // Hr write acknowledged → READ BINARY 0..2 (Hs length)
        let res = driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 10");
        match res {
            ReaderApduProgress::InProgress(bytes) => {
                assert_eq!(bytes, [0x00, 0xB0, 0x00, 0x00, 0x02]);
            }
            _ => panic!("expected READ BINARY for Hs length, got {res:?}"),
        }
        // Hs NDEF length = 186 bytes → READ BINARY 2..188 (Hs data)
        let res = driver
            .process_rapdu(&[0x00, 0xBA, 0x90, 0x00])
            .expect("failed to process rapdu 11");
        match res {
            ReaderApduProgress::InProgress(bytes) => {
                assert_eq!(bytes, [0x00, 0xB0, 0x00, 0x02, 0xBA]);
            }
            _ => panic!("expected READ BINARY for Hs data, got {res:?}"),
        }
        // Hs NDEF (186 bytes from multipaz — BLE OOB has no UUID; Hr UUID used as fallback)
        let res = driver
            .process_rapdu(&[
                0x91, 0x02, 0x0F, 0x48, 0x73, 0x15, 0xD1, 0x02, 0x09, 0x61, 0x63, 0x01, 0x01, 0x30,
                0x01, 0x04, 0x6D, 0x64, 0x6F, 0x63, 0x1C, 0x1E, 0x58, 0x04, 0x69, 0x73, 0x6F, 0x2E,
                0x6F, 0x72, 0x67, 0x3A, 0x31, 0x38, 0x30, 0x31, 0x33, 0x3A, 0x64, 0x65, 0x76, 0x69,
                0x63, 0x65, 0x65, 0x6E, 0x67, 0x61, 0x67, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x6D, 0x64,
                0x6F, 0x63, 0xA2, 0x00, 0x63, 0x31, 0x2E, 0x30, 0x01, 0x82, 0x01, 0xD8, 0x18, 0x58,
                0x4B, 0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, 0x5E, 0xB2, 0x16, 0xAC, 0x43,
                0x77, 0xD2, 0x9E, 0xA6, 0x1C, 0xF1, 0x3E, 0x71, 0x24, 0x7A, 0x45, 0xC2, 0xE5, 0x60,
                0xF0, 0x1E, 0xCC, 0x66, 0x22, 0x1E, 0x2D, 0xB7, 0x1C, 0x02, 0xD9, 0x75, 0x05, 0x22,
                0x58, 0x20, 0x07, 0x29, 0x3E, 0x94, 0x76, 0x00, 0xB0, 0x34, 0x39, 0x8B, 0xBA, 0xE0,
                0x12, 0xF3, 0xF9, 0xDF, 0x49, 0x69, 0x2B, 0x73, 0x77, 0xE8, 0x8A, 0xDF, 0x46, 0x53,
                0x24, 0x78, 0xB2, 0x97, 0xE8, 0x64, 0x5A, 0x20, 0x03, 0x01, 0x61, 0x70, 0x70, 0x6C,
                0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 0x62, 0x6C,
                0x75, 0x65, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x2E, 0x6C, 0x65, 0x2E, 0x6F, 0x6F, 0x62,
                0x30, 0x02, 0x1C, 0x01, 0x90, 0x00,
            ])
            .expect("failed to process rapdu 12");
        assert!(matches!(res, ReaderApduProgress::Done(_)));
    }

    #[test_log::test]
    fn samsung_wallet() {
        let mut driver = ReaderApduHandoverDriver::new().0;
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 1");
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 2");
        driver
            .process_rapdu(&[
                0x00, 0x0F, 0x20, 0x7F, 0xFF, 0x7F, 0xFF, 0x04, 0x06, 0xE1, 0x04, 0x7F, 0xFF, 0x00,
                0xFF, 0x90, 0x00,
            ])
            .expect("failed to process rapdu 3");
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 4");
        driver
            .process_rapdu(&[0x00, 0xE0, 0x90, 0x00])
            .expect("failed to process rapdu 5");
        let res = driver
            .process_rapdu(&[
                0x91, 0x02, 0x0F, 0x48, 0x73, 0x15, 0xD1, 0x02, 0x09, 0x61, 0x63, 0x01, 0x01, 0x30,
                0x01, 0x04, 0x6D, 0x64, 0x6F, 0x63, 0x1A, 0x20, 0x29, 0x01, 0x61, 0x70, 0x70, 0x6C,
                0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 0x62, 0x6C,
                0x75, 0x65, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x2E, 0x6C, 0x65, 0x2E, 0x6F, 0x6F, 0x62,
                0x30, 0x02, 0x1C, 0x01, 0x11, 0x07, 0x10, 0x3C, 0x8E, 0x43, 0x09, 0xD1, 0x39, 0xA6,
                0x87, 0x49, 0xC5, 0x77, 0xEE, 0x87, 0xC0, 0xBD, 0x03, 0x19, 0x00, 0x40, 0x0F, 0x09,
                0x53, 0x61, 0x6D, 0x73, 0x75, 0x6E, 0x67, 0x20, 0x57, 0x61, 0x6C, 0x6C, 0x65, 0x74,
                0x5C, 0x1E, 0x58, 0x04, 0x69, 0x73, 0x6F, 0x2E, 0x6F, 0x72, 0x67, 0x3A, 0x31, 0x38,
                0x30, 0x31, 0x33, 0x3A, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x65, 0x6E, 0x67, 0x61,
                0x67, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x6D, 0x64, 0x6F, 0x63, 0xA2, 0x00, 0x63, 0x31,
                0x2E, 0x30, 0x01, 0x82, 0x01, 0xD8, 0x18, 0x58, 0x4B, 0xA4, 0x01, 0x02, 0x20, 0x01,
                0x21, 0x58, 0x20, 0x7B, 0x3A, 0xB8, 0xD9, 0xE2, 0x19, 0x64, 0xD2, 0xCE, 0x1C, 0xBF,
                0x28, 0xAB, 0x7F, 0xB7, 0xFC, 0xAC, 0x9D, 0x81, 0xC0, 0x91, 0x5B, 0xB6, 0x0D, 0xF4,
                0x7D, 0x0A, 0xD5, 0xB5, 0x53, 0x2D, 0xB4, 0x22, 0x58, 0x20, 0x65, 0x2D, 0x2E, 0x93,
                0x5E, 0x35, 0xEB, 0x51, 0x9A, 0xE8, 0xFD, 0xB3, 0xAD, 0xA2, 0x0F, 0xED, 0x2D, 0x0A,
                0xBC, 0xB3, 0x2C, 0x15, 0xAB, 0x46, 0xEC, 0x1A, 0x1D, 0xC8, 0x70, 0x45, 0x5C, 0xEA,
                0x90, 0x00,
            ])
            .expect("failed to process rapdu 6");
        assert!(matches!(res, ReaderApduProgress::Done(_)));
    }

    /// Full round-trip transcript from a manual test session with Google Wallet on Android.
    #[test_log::test]
    fn google_wallet() {
        let mut driver = ReaderApduHandoverDriver::new().0;
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 1");
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 2");
        driver
            .process_rapdu(&[
                0x00, 0x0F, 0x20, 0x7F, 0xFF, 0x7F, 0xFF, 0x04, 0x06, 0xE1, 0x04, 0x7F, 0xFF, 0x00,
                0x00, 0x90, 0x00,
            ])
            .expect("failed to process rapdu 3");
        driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 4");
        driver
            .process_rapdu(&[0x00, 0x1F, 0x90, 0x00])
            .expect("failed to process rapdu 5");
        // Device returns Tp (TNEP Service Parameter) record
        let res = driver
            .process_rapdu(&[
                0xD1, 0x02, 0x1A, 0x54, 0x70, 0x10, 0x13, 0x75, 0x72, 0x6E, 0x3A, 0x6E, 0x66, 0x63,
                0x3A, 0x73, 0x6E, 0x3A, 0x68, 0x61, 0x6E, 0x64, 0x6F, 0x76, 0x65, 0x72, 0x00, 0x10,
                0x0F, 0xFF, 0xFF, 0x90, 0x00,
            ])
            .expect("failed to process rapdu 6");
        // Driver should respond with UPDATE BINARY writing Ts (Service Select)
        let expected_ts_apdu =
            hex::decode("00d600001b0019d1021454731375726e3a6e66633a736e3a68616e646f766572")
                .unwrap();
        match res {
            ReaderApduProgress::InProgress(bytes) => assert_eq!(bytes, expected_ts_apdu),
            _ => panic!("expected InProgress with Ts UPDATE BINARY, got {res:?}"),
        }
        // Ts write acknowledged → READ BINARY 0..2 (Te length)
        let res = driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 7");
        match res {
            ReaderApduProgress::InProgress(bytes) => {
                assert_eq!(bytes, [0x00, 0xB0, 0x00, 0x00, 0x02]);
            }
            _ => panic!("expected READ BINARY for Te length, got {res:?}"),
        }
        // Te NDEF length = 6 bytes → READ BINARY 2..8 (Te data)
        let res = driver
            .process_rapdu(&[0x00, 0x06, 0x90, 0x00])
            .expect("failed to process rapdu 8");
        match res {
            ReaderApduProgress::InProgress(bytes) => {
                assert_eq!(bytes, [0x00, 0xB0, 0x00, 0x02, 0x06]);
            }
            _ => panic!("expected READ BINARY for Te data, got {res:?}"),
        }
        // Te data (TNEP status 0x00 = success) → UPDATE BINARY Hr
        let res = driver
            .process_rapdu(&[0xD1, 0x02, 0x01, 0x54, 0x65, 0x00, 0x90, 0x00])
            .expect("failed to process rapdu 9");
        let ReaderApduProgress::InProgress(hr_apdu) = res else {
            panic!("expected InProgress with Hr UPDATE BINARY, got {res:?}");
        };
        // Hr APDU: UPDATE BINARY header (5) + 2-byte NDEF length + 164-byte NDEF = 171 bytes total.
        // NDEF: Hr(26) + ReaderEngagement(50) + BLE OOB(58) + NFC Config(30) = 164 bytes.
        // The NDEF contains a random UUID in the BLE OOB record; verify the deterministic portions.
        assert_eq!(hr_apdu.len(), 171);
        assert_eq!(&hr_apdu[..5], &[0x00, 0xD6, 0x00, 0x00, 0xA6]);
        // bytes 5..125: NDEF length prefix + Hr record + ReaderEngagement record + BLE OOB through UUID prefix
        #[rustfmt::skip]
        assert_eq!(&hr_apdu[5..125], &[
            0x00, 0xA4, // NDEF length (164)
            // Hr record
            0x91, 0x02, 0x15, 0x48, 0x72, 0x15, 0x91, 0x02, 0x04, 0x61, 0x63, 0x01, 0x01, 0x30,
            0x00, 0x51, 0x02, 0x06, 0x61, 0x63, 0x01, 0x03, 0x6E, 0x66, 0x63, 0x00,
            // ReaderEngagement record
            0x1C, 0x1E, 0x06, 0x0A, 0x69, 0x73, 0x6F, 0x2E, 0x6F, 0x72, 0x67, 0x3A, 0x31, 0x38,
            0x30, 0x31, 0x33, 0x3A, 0x72, 0x65, 0x61, 0x64, 0x65, 0x72, 0x65, 0x6E, 0x67, 0x61,
            0x67, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x6D, 0x64, 0x6F, 0x63, 0x72, 0x65, 0x61, 0x64,
            0x65, 0x72, 0xA1, 0x00, 0x63, 0x31, 0x2E, 0x30,
            // BLE OOB record: flags, type_len, payload_len, id_len, type, id, payload prefix (before UUID)
            0x1A, 0x20, 0x15, 0x01, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F,
            0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 0x62, 0x6C, 0x75, 0x65, 0x74, 0x6F, 0x6F, 0x74,
            0x68, 0x2E, 0x6C, 0x65, 0x2E, 0x6F, 0x6F, 0x62, 0x30, 0x02, 0x1C, 0x03, 0x11, 0x07,
        ]);
        // bytes 125..141: random UUID (16 bytes) — not checked
        // bytes 141..171: NFC Carrier Config record (30 bytes, 6-byte payload per interop workaround)
        assert_eq!(
            &hr_apdu[141..],
            &[
                0x5C, 0x11, 0x06, 0x03, 0x69, 0x73, 0x6F, 0x2E, 0x6F, 0x72, 0x67, 0x3A, 0x31, 0x38,
                0x30, 0x31, 0x33, 0x3A, 0x6E, 0x66, 0x63, 0x6E, 0x66, 0x63, 0x01, 0x01, 0xFF, 0x02,
                0xFF, 0xFF,
            ]
        );
        // Hr write acknowledged → READ BINARY 0..2 (Hs length)
        let res = driver
            .process_rapdu(&[0x90, 0x00])
            .expect("failed to process rapdu 10");
        match res {
            ReaderApduProgress::InProgress(bytes) => {
                assert_eq!(bytes, [0x00, 0xB0, 0x00, 0x00, 0x02]);
            }
            _ => panic!("expected READ BINARY for Hs length, got {res:?}"),
        }
        // Hs NDEF length = 204 bytes → READ BINARY 2..206 (Hs data)
        let res = driver
            .process_rapdu(&[0x00, 0xCC, 0x90, 0x00])
            .expect("failed to process rapdu 11");
        match res {
            ReaderApduProgress::InProgress(bytes) => {
                assert_eq!(bytes, [0x00, 0xB0, 0x00, 0x02, 0xCC]);
            }
            _ => panic!("expected READ BINARY for Hs data, got {res:?}"),
        }
        // Hs NDEF data (204 bytes from Google Wallet) → Done
        let res = driver
            .process_rapdu(&[
                0x91, 0x02, 0x0F, 0x48, 0x73, 0x15, 0xD1, 0x02, 0x09, 0x61, 0x63, 0x01, 0x01, 0x30,
                0x01, 0x04, 0x6D, 0x64, 0x6F, 0x63, 0x1C, 0x1E, 0x58, 0x04, 0x69, 0x73, 0x6F, 0x2E,
                0x6F, 0x72, 0x67, 0x3A, 0x31, 0x38, 0x30, 0x31, 0x33, 0x3A, 0x64, 0x65, 0x76, 0x69,
                0x63, 0x65, 0x65, 0x6E, 0x67, 0x61, 0x67, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x6D, 0x64,
                0x6F, 0x63, 0xA2, 0x00, 0x63, 0x31, 0x2E, 0x30, 0x01, 0x82, 0x01, 0xD8, 0x18, 0x58,
                0x4B, 0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, 0xE8, 0x37, 0xB6, 0x08, 0x59,
                0x1A, 0xC6, 0x39, 0x91, 0xA9, 0xA2, 0x14, 0xED, 0x50, 0xC9, 0xA1, 0x90, 0x3F, 0x26,
                0xCA, 0x19, 0xF1, 0x6A, 0xFD, 0x28, 0xF7, 0x78, 0xD4, 0x8E, 0x3C, 0x94, 0x6C, 0x22,
                0x58, 0x20, 0xB3, 0x8C, 0xA0, 0xDA, 0xF7, 0xD7, 0x96, 0xDF, 0x4E, 0x5B, 0xCA, 0x0D,
                0xA3, 0x70, 0x50, 0xD5, 0x41, 0x21, 0xBA, 0xBA, 0xED, 0xFA, 0x39, 0xA7, 0x96, 0x27,
                0x6B, 0x05, 0x3C, 0x03, 0xB6, 0xC7, 0x5A, 0x20, 0x15, 0x01, 0x61, 0x70, 0x70, 0x6C,
                0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 0x62, 0x6C,
                0x75, 0x65, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x2E, 0x6C, 0x65, 0x2E, 0x6F, 0x6F, 0x62,
                0x30, 0x02, 0x1C, 0x01, 0x11, 0x07, 0xB8, 0x9C, 0x57, 0x93, 0xB4, 0xC0, 0x02, 0xA4,
                0xDB, 0x4F, 0x1E, 0x1B, 0xDD, 0xB7, 0x4D, 0xE3, 0x90, 0x00,
            ])
            .expect("failed to process rapdu 12");
        assert!(matches!(res, ReaderApduProgress::Done(_)));
    }
}
