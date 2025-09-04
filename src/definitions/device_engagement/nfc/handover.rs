use crate::definitions::device_engagement::nfc::{
    apdu::{self},
    ndef::{self, CarrierInfo, NFC_MAX_PAYLOAD_SIZE, NFC_MAX_PAYLOAD_SIZE_BYTES},
    util::{IntoRaw, KnownOrRaw},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApduError {
    #[error("Invalid APDU command")]
    InvalidApdu,
    #[error("NDEF handover failed: {0}")]
    NdefHandoverError(#[from] ndef::HandoverError),
}

#[derive(Debug, Clone)]
pub struct ApduHandoverDriver {
    state: ndef::HandoverState,
    selected_file: Option<KnownOrRaw<u16, apdu::FileId>>,
    ndef_send: Option<Vec<u8>>,
    ndef_recv: NdefUpdateDriver,
    negotiated: bool,
}

#[derive(Debug, Clone)]
struct NdefUpdateDriver {
    bytes: Vec<u8>,
}

impl NdefUpdateDriver {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }
    pub fn reset(&mut self) {
        self.bytes.clear();
    }
    pub fn handle(
        &mut self,
        offset: usize,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, apdu::ResponseCode> {
        if offset == 1 {
            // We don't support sending the file length byte-by-byte.
            // It must be sent all at once.
            return Err(apdu::ResponseCode::Unspecified);
        }
        let (file_length, bytes) = if offset == 0 && bytes.len() >= 2 {
            (
                Some(u16::from_be_bytes([bytes[0], bytes[1]]) as usize),
                &bytes[2..],
            )
        } else {
            (None, bytes)
        };
        match (offset, file_length, bytes.len()) {
            (0, Some(file_length), 0) if file_length != 0 => {
                // Finalize file - we've written the entire file.
                if self.bytes.len() == file_length {
                    let mut ret = Vec::new();
                    std::mem::swap(&mut ret, &mut self.bytes);
                    Ok(Some(ret))
                } else {
                    self.reset();
                    Err(apdu::ResponseCode::ConditionsNotSatisfied)
                }
            }
            (0, Some(file_length), _) => {
                // Reset file
                self.reset();
                if file_length == bytes.len() {
                    // Got entire file
                    self.bytes.extend_from_slice(bytes);
                    let mut ret = Vec::new();
                    std::mem::swap(&mut ret, &mut self.bytes);
                    Ok(Some(ret))
                } else {
                    self.bytes.extend_from_slice(bytes);
                    Ok(None)
                }
            }
            (0, None, _) => {
                self.reset();
                Err(apdu::ResponseCode::Unspecified)
            }
            (offset_plus_two, _, _) => {
                // Subtract two to account for the fact that the "file" (according to the spec)
                // has the length (u16) prepended to it.
                let offset = offset_plus_two - 2;
                if offset != self.bytes.len() {
                    // We don't support non-contiguous writes
                    // TODO: Do we have to support this?
                    self.reset();
                    Err(apdu::ResponseCode::ConditionsNotSatisfied)
                } else {
                    self.bytes.extend_from_slice(bytes);
                    Ok(None)
                }
            }
        }
    }
}

const APDU_MAX_SIZE: usize = NFC_MAX_PAYLOAD_SIZE + 10;
const APDU_MAX_SIZE_BYTES: [u8; 2] = u16::to_be_bytes(APDU_MAX_SIZE as u16);

#[rustfmt::skip]
const CC_FILE_TEMPLATE: &[u8] = &[
    0x00, 0x0f, // Length of the CC file
    0x20, // Mapping version
    APDU_MAX_SIZE_BYTES[0], APDU_MAX_SIZE_BYTES[1], // Maximum R-APDU (reader -> app) size
    APDU_MAX_SIZE_BYTES[0], APDU_MAX_SIZE_BYTES[1], // Maximum C-APDU (app -> reader) size
    0x04, // NDEF file control TLV
    0x06, // Length of TLV
    0xe1, 0x04, // File ID: NDEF file (0xe104)
    NFC_MAX_PAYLOAD_SIZE_BYTES[0], NFC_MAX_PAYLOAD_SIZE_BYTES[1],
    0x00, // Read access condition
    0x00, // Write access condition. 00 for negotiated, ff for static
];

fn cc_file(negotiated: bool) -> Vec<u8> {
    let mut cc = CC_FILE_TEMPLATE.to_vec();
    cc[14] = if negotiated { 0x00 } else { 0xff };
    cc
}

impl ApduHandoverDriver {
    pub fn new(negotiated: bool) -> Self {
        Self {
            state: ndef::HandoverState::Init,
            negotiated,
            selected_file: None,
            ndef_send: None,
            ndef_recv: NdefUpdateDriver::new(),
        }
    }

    /// Perform a full reset of the APDU driver state.
    pub fn reset(&mut self) {
        *self = Self::new(self.negotiated);
    }

    // If we have carrier info, return it and reset the state.
    pub fn get_carrier_info(&mut self) -> Option<CarrierInfo> {
        if matches!(&self.state, ndef::HandoverState::Done(_)) {
            let mut state = ndef::HandoverState::Init;
            std::mem::swap(&mut self.state, &mut state);
            let ndef::HandoverState::Done(carrier_info) = state else {
                // Guaranteed unreachable
                return None;
            };
            Some(carrier_info)
        } else {
            None
        }
    }

    fn process_apdu_inner(&mut self, command: &[u8]) -> apdu::Response {
        let command = match apdu::Apdu::parse(command) {
            Ok(command) => command,
            Err(ret) => return ret,
        };

        tracing::debug!("Received APDU: {:?}", command);

        match command {
            apdu::Apdu::SelectFile {
                control_info,
                file_id,
                ..
            } => match file_id {
                KnownOrRaw::Known(apdu::FileId::CapabilityContainer) => {
                    self.selected_file = Some(file_id);
                    let response = match control_info.get_payload(&u16::to_be_bytes(
                        apdu::FileId::CapabilityContainer.into_raw(),
                    )) {
                        Ok(payload) => payload,
                        Err(err) => return err,
                    };
                    self.ndef_send = Some(cc_file(self.negotiated));
                    response
                }
                KnownOrRaw::Known(apdu::FileId::NdefFile) => {
                    // Subsequent calls to SELECT FILE should not refresh the contents of the file,
                    // so we should not prepare a new NDEF message.
                    if self.selected_file == Some(file_id) {
                        return match control_info
                            .get_payload(&u16::to_be_bytes(apdu::FileId::NdefFile.into_raw()))
                        {
                            Ok(payload) => payload,
                            Err(err) => err,
                        };
                    }

                    let handover_resp = if self.negotiated {
                        ndef::get_handover_ndef_response(&self.state, &[])
                    } else {
                        ndef::get_static_handover_ndef_response()
                    };
                    match handover_resp {
                        Ok(ndef::HandoverResponse { new_state, ndef }) => {
                            let response = match control_info
                                .get_payload(&u16::to_be_bytes(apdu::FileId::NdefFile.into_raw()))
                            {
                                Ok(payload) => payload,
                                Err(err) => return err,
                            };
                            self.state = new_state;
                            self.ndef_send = Some(
                                [&u16::to_be_bytes(ndef.len() as u16) as &[u8], &ndef].concat(),
                            );
                            self.selected_file = Some(file_id);
                            response
                        }
                        Err(err) => {
                            tracing::error!("Handover error: {:?}", err);
                            self.reset();
                            apdu::ResponseCode::Unspecified.into()
                        }
                    }
                }
                KnownOrRaw::Unknown(_) => apdu::ResponseCode::FileOrApplicationNotFound.into(),
            },
            apdu::Apdu::SelectAid {
                control_info, aid, ..
            } => {
                const APDU_AID_MDOC: &[u8] = &[0xA0, 0x00, 0x00, 0x02, 0x48, 0x04, 0x00];
                const APDU_AID_NDEF_APPLICATION: &[u8] =
                    &[0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
                match aid {
                    APDU_AID_MDOC | APDU_AID_NDEF_APPLICATION => {
                        match control_info.get_payload(aid) {
                            Ok(response) => response,
                            Err(err) => err,
                        }
                    }
                    _ => apdu::ResponseCode::FileOrApplicationNotFound.into(),
                }
            }
            apdu::Apdu::ReadBinary { slice } => {
                let Some(read_bytes) = self.ndef_send.as_ref() else {
                    return apdu::ResponseCode::ConditionsNotSatisfied.into();
                };
                if slice.len() > read_bytes.len() {
                    return apdu::ResponseCode::IncorrectLength.into();
                }
                let data = read_bytes[slice.start..slice.end].to_vec();
                apdu::Response {
                    code: apdu::ResponseCode::Ok,
                    payload: data,
                }
            }
            apdu::Apdu::UpdateBinary { offset, data } => {
                if !self.negotiated {
                    return apdu::ResponseCode::ConditionsNotSatisfied.into();
                }
                match self.ndef_recv.handle(offset, data) {
                    Ok(Some(msg)) => match ndef::get_handover_ndef_response(&self.state, &msg) {
                        Ok(ndef::HandoverResponse { new_state, ndef }) => {
                            self.state = new_state;
                            self.ndef_send = Some(ndef);
                            apdu::ResponseCode::Ok.into()
                        }
                        Err(err) => {
                            tracing::error!("Handover error: {:?}", err);
                            self.reset();
                            apdu::ResponseCode::Unspecified.into()
                        }
                    },
                    Ok(None) => apdu::ResponseCode::Ok.into(),
                    Err(resp) => {
                        self.reset();
                        resp.into()
                    }
                }
            }
        }
    }

    pub fn process_apdu(&mut self, command: &[u8]) -> Vec<u8> {
        self.process_apdu_inner(command).into()
    }
}
