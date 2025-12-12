use crate::definitions::device_engagement::nfc::{
    apdu::{
        self,
        select::{ControlInfo, Occurrence},
        Apdu, FileId,
    },
    cc_file,
    ndef_handover_reader::{ReaderHandoverState, ReaderNegotiatedCarrierInfo},
    util::KnownOrRaw,
    APDU_AID_NDEF_APPLICATION, CC_FILE_TEMPLATE,
};

use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum ReaderApduError {
    #[error("CC File is invalid")]
    CCFileMismatch,
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
    negotiated: bool,
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
    pub fn new(negotiated: bool) -> (Self, Vec<u8>) {
        if negotiated {
            unimplemented!(
                "Negotiated handover is not implemented yet. Please use static handover."
            );
        }
        let self_ = Self {
            state: ReaderHandoverState::WaitingForAidResponse,
            negotiated,
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
                if ndef_recv != cc_file(self.negotiated) {
                    return Err(ReaderApduError::CCFileMismatch);
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
                    let carrier_info = ReaderNegotiatedCarrierInfo::parse_ndef_message(
                        &ndef_recv,
                        self.negotiated,
                    )
                    .map_err(ReaderApduError::NdefMessageError)?;
                    self.state = ReaderHandoverState::Done;
                    Ok(ReaderApduProgress::Done(Box::new(carrier_info)))
                }
            }
            ReaderHandoverState::Done => Err(ReaderApduError::Done),
        }
    }
}
