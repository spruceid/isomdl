use crate::definitions::device_engagement::nfc::{
    apdu::{
        self,
        select::{ControlInfo, Occurrence},
        Apdu, FileId,
    },
    ndef_handover_reader::{ReaderHandoverState, ReaderNegotiatedCarrierInfo},
    util::KnownOrRaw,
    APDU_AID_NDEF_APPLICATION, CC_FILE_TEMPLATE,
};

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
}

#[derive(Debug, Clone)]
pub enum ReaderApduProgress {
    InProgress(Vec<u8>),
    Done(Box<ReaderNegotiatedCarrierInfo>),
}

impl ReaderApduHandoverDriver {
    /// Create a new APDU handover driver.
    ///
    /// * `negotiated`: true -> use negotiated handover (not implemented yet), false -> use static handover.
    /// * `strict`: require selecting the MDOC AID before responding to NDEF reads. If strict is false, we will always return NDEF messages.
    pub fn new() -> (Self, Vec<u8>) {
        let self_ = Self {
            state: ReaderHandoverState::WaitingForAidResponse,
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
        match self.state {
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
                self.state = ReaderHandoverState::WaitingForNdefReadResponse;
                let apdu = Apdu::ReadBinary { slice: 0..2 };
                Ok(ReaderApduProgress::InProgress(apdu.to_bytes()))
            }
            ReaderHandoverState::WaitingForNdefReadResponse => {
                let ndef_recv = rapdu.payload;
                if ndef_recv.len() == 2 {
                    let ndef_len = u16::from_be_bytes(*ndef_recv.first_chunk::<2>().unwrap());
                    let apdu = Apdu::ReadBinary {
                        slice: 2..2 + ndef_len as usize, // TODO can it be larger than 1 chunk?
                    };
                    Ok(ReaderApduProgress::InProgress(apdu.to_bytes()))
                } else {
                    let carrier_info = ReaderNegotiatedCarrierInfo::parse_ndef_message(&ndef_recv)
                        .map_err(ReaderApduError::NdefMessageError)?;
                    self.state = ReaderHandoverState::Done;
                    Ok(ReaderApduProgress::Done(Box::new(carrier_info)))
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

    #[test]
    /// Transcript from a manual test
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
        let res = driver.process_rapdu(&[
            0xD1, 0x02, 0x1A, 0x54, 0x70, 0x10, 0x13, 0x75, 0x72, 0x6E, 0x3A, 0x6E, 0x66, 0x63,
            0x3A, 0x73, 0x6E, 0x3A, 0x68, 0x61, 0x6E, 0x64, 0x6F, 0x76, 0x65, 0x72, 0x00, 0x00,
            0x0F, 0xFF, 0xFF, 0x90, 0x00,
        ]);
        assert_eq!(
            res.unwrap_err().to_string(),
            "NDEF decoding failure: negotiated handover not supported"
        );
    }
}
