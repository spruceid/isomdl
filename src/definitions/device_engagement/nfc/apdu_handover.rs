use crate::definitions::{
    device_engagement::nfc::{
        apdu::{self},
        ndef_handover::{
            self, HandoverError, NegotiatedCarrierInfo, NFC_MAX_PAYLOAD_SIZE,
            NFC_MAX_PAYLOAD_SIZE_BYTES,
        },
        util::{IntoRaw, KnownOrRaw},
    },
    Security,
};

use thiserror::Error;
use uuid::Uuid;

pub(crate) const APDU_AID_MDOC: &[u8] = &[0xA0, 0x00, 0x00, 0x02, 0x48, 0x04, 0x00];
pub(crate) const APDU_AID_NDEF_APPLICATION: &[u8] = &[0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

#[derive(Clone)]
pub struct StaticHandoverState {
    pub uuid: uuid::Uuid,
    pub private_key: Vec<u8>,
    pub security: Security,
}

impl StaticHandoverState {
    pub fn new() -> anyhow::Result<Self> {
        let (private_key, security) = crate::presentation::device::ephemeral_key()
            .map_err(|e| anyhow::anyhow!("Failed to generate holder keys: {e}"))?;

        Ok(Self {
            uuid: Uuid::new_v4(),
            private_key,
            security,
        })
    }
}

impl std::fmt::Debug for StaticHandoverState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticHandoverState")
            .field("uuid", &self.uuid)
            .field("private_key", &"<redacted>")
            .field("security", &self.security)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum ApduError {
    #[error("Invalid APDU command")]
    InvalidApdu,
    #[error("NDEF handover failed: {0}")]
    NdefHandoverError(#[from] ndef_handover::HandoverError),
}

// Stub out the real NdefUpdateDriver until we have negotiated handover finished.
#[derive(Debug, Clone)]
struct NdefUpdateDriver;
impl NdefUpdateDriver {
    pub fn new() -> Self {
        Self
    }
}

const APDU_MAX_SIZE: usize = NFC_MAX_PAYLOAD_SIZE + 10;
const APDU_MAX_SIZE_BYTES: [u8; 2] = u16::to_be_bytes(APDU_MAX_SIZE as u16);

#[rustfmt::skip]
pub(super) const CC_FILE_TEMPLATE: &[u8] = &[
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

pub(super) fn cc_file(negotiated: bool) -> Vec<u8> {
    let mut cc = CC_FILE_TEMPLATE.to_vec();
    cc[14] = if negotiated { 0x00 } else { 0xff };
    cc
}

#[derive(Debug, Clone)]
pub struct ApduHandoverDriver {
    /// Do we respond to NDEF reads even if we haven't selected the MDOC application yet?
    strict: bool,
    state: ndef_handover::HandoverState,
    selected_file: Option<KnownOrRaw<u16, apdu::FileId>>,
    ndef_send: Option<Vec<u8>>,
    ndef_recv: NdefUpdateDriver,
    negotiated: bool,
    static_ble: StaticHandoverState,
    listen_for_ndef: bool,
}

impl ApduHandoverDriver {
    /// Create a new APDU handover driver.
    ///
    /// * `negotiated`: true -> use negotiated handover (not implemented yet), false -> use static handover.
    /// * `strict`: require selecting the MDOC AID before responding to NDEF reads. If strict is false, we will always return NDEF messages.
    pub fn new(negotiated: bool, strict: bool) -> Result<Self, HandoverError> {
        if negotiated {
            return Err(anyhow::anyhow!(
                "Negotiated handover is not implemented yet. Please use static handover."
            )
            .into());
        }
        Ok(Self {
            strict,
            state: ndef_handover::HandoverState::Init,
            negotiated,
            selected_file: None,
            ndef_send: None,
            ndef_recv: NdefUpdateDriver::new(),
            static_ble: StaticHandoverState::new()?,
            listen_for_ndef: false,
        })
    }

    /// Perform a full reset of the APDU driver state, except for the static BLE state.
    pub fn reset(&mut self) {
        self.state = ndef_handover::HandoverState::Init;
        self.selected_file = None;
        self.ndef_send = None;
        self.ndef_recv = NdefUpdateDriver::new();
        self.listen_for_ndef = false;
    }

    pub fn regenerate_static_ble_keys(&mut self) -> Result<(), HandoverError> {
        self.static_ble = StaticHandoverState::new()?;
        Ok(())
    }

    // If we have carrier info, return it and reset the state.
    pub fn get_carrier_info(&mut self) -> Option<Box<NegotiatedCarrierInfo>> {
        if matches!(&self.state, ndef_handover::HandoverState::Done(_)) {
            let mut state = ndef_handover::HandoverState::Init;
            std::mem::swap(&mut self.state, &mut state);
            let ndef_handover::HandoverState::Done(carrier_info) = state else {
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
                // BREAKING SPEC: We ignore occurrence because NDEF doesn't require indexing
                //                multiple files with the same ID. This should have no impact
                //                since we only respond to requests for NDEF communication.
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
                        todo!("Implement negotiated handover");
                    } else {
                        ndef_handover::get_static_handover_ndef_response(self.static_ble.clone())
                    };
                    match handover_resp {
                        Ok(ndef_handover::HandoverResponse { new_state, ndef }) => {
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
            } => match aid {
                APDU_AID_MDOC => match control_info.get_payload(aid) {
                    Ok(response) => {
                        self.listen_for_ndef = true;
                        response
                    }
                    Err(err) => err,
                },
                APDU_AID_NDEF_APPLICATION => match control_info.get_payload(aid) {
                    Ok(response) => response,
                    Err(err) => err,
                },
                _ => apdu::ResponseCode::FileOrApplicationNotFound.into(),
            },
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
                _ = offset;
                _ = data;
                todo!("Implement negotiated handover");
            }
        }
    }

    pub fn process_apdu(&mut self, command: &[u8]) -> Vec<u8> {
        let res = self.process_apdu_inner(command);
        if !self.strict || self.listen_for_ndef {
            res.into()
        } else {
            apdu::Response::from(apdu::ResponseCode::ConditionsNotSatisfied).into()
        }
    }
}

#[cfg(test)]
mod test {
    use crate::definitions::device_engagement::nfc::{
        ReaderApduHandoverDriver, ReaderApduProgress,
    };

    use super::*;

    #[test]
    fn roundtrip_static_handover() {
        let mut holder = ApduHandoverDriver::new(false, false)
            .expect("failed to build holder apdu handover driver");
        let (mut reader, mut apdu) = ReaderApduHandoverDriver::new();
        let mut rapdu;
        for _ in 0..5 {
            rapdu = holder.process_apdu(&apdu);
            apdu = match reader
                .process_rapdu(&rapdu)
                .expect("failed to process rpdu")
            {
                ReaderApduProgress::InProgress(r) => r,
                ReaderApduProgress::Done(_) => {
                    panic!("there should be a follow-up apdu")
                }
            };
        }
        let rapdu = holder.process_apdu(&apdu);
        let res = reader
            .process_rapdu(&rapdu)
            .expect("failed to process rpdu");
        assert!(matches!(res, ReaderApduProgress::Done(_)));
    }
}
