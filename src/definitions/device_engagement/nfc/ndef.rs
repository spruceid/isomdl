use std::borrow::Cow;

use ndef_rs::payload::RecordPayload;
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::definitions::device_engagement::nfc::{
    ndef_parser,
    util::{ByteVecDisplayAsHex, DisplayBytesAsHex},
};

pub(super) const NFC_MAX_PAYLOAD_SIZE: usize = 255 - 2; // 255 minus 2 bytes for the size
pub(super) const NFC_MAX_PAYLOAD_SIZE_BYTES: [u8; 2] = (NFC_MAX_PAYLOAD_SIZE as u16).to_be_bytes();

#[derive(Debug, Clone)]
pub enum HandoverState {
    Init,
    WaitingForServiceSelect,
    WaitingForHandoverRequest,
    Done(CarrierInfo),
}

#[derive(Error, Debug)]
pub enum HandoverError {
    #[error("Expected no NDEF message, but received one")]
    UnexpectedNdef(Vec<u8>),
    #[error("Expected NDEF message, but received none")]
    MissingNdef,
    #[error("Invalid NDEF message received: {0}, {1}")]
    InvalidNdef(#[source] ndef_parser::ReadRecordError, ByteVecDisplayAsHex),
    #[error("Failed to find NDEF record {0:?} in message {1}")]
    FailedToFindNdefRecord(RecordType, String),
    #[error("Failed to build NDEF message: {0}")]
    FailedToBuildNdef(
        #[source]
        #[from]
        ndef_rs::error::NdefError,
    ),
    // ndef_rs exposes anyhow in a public API, unfortunately.
    #[error("Failed to build NDEF message: {0}")]
    FailedToBuildNdefTypeErased(#[source] anyhow::Error),
    #[error("Unexpected state {state:?} for {location}")]
    UnexpectedState {
        state: HandoverState,
        location: String,
    },
    #[error("{0}")]
    AdHoc(
        #[source]
        #[from]
        anyhow::Error,
    ),
}

#[derive(Debug, Clone, Copy, strum_macros::EnumIter)]
pub enum RecordType {
    /// From Wallet
    TnepServiceParameter,
    /// From Reader
    TnepServiceSelect,
    /// From Wallet
    TnepStatus,
    /// From Reader
    HandoverRequest,
    /// From Wallet
    HandoverSelect,
}

#[allow(dead_code)]
impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::TnepServiceParameter => "Tp",
            RecordType::TnepServiceSelect => "Ts",
            RecordType::TnepStatus => "Te",
            RecordType::HandoverRequest => "Hr",
            RecordType::HandoverSelect => "Hs",
        }
    }
    pub fn as_bytes(&self) -> &'static [u8] {
        self.as_str().as_bytes()
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        for record_type in RecordType::iter() {
            if record_type.as_bytes() == bytes {
                return Some(record_type);
            }
        }
        None
    }
    pub fn from_str(s: &str) -> Option<Self> {
        Self::from_bytes(s.as_bytes())
    }
}

// ndef_rs provides ExternalPayload, but this seems to have semantic meaning.
// We'll implement our own form of it with no implied semantics.
// This also allows us to use local borrows (since ExternalPayload only uses 'static),
// preventing unnecessary copies :)
#[derive(Debug, Clone)]
pub(super) struct RawPayload<'r, 'p> {
    pub record_type: &'r [u8],
    pub payload: &'p [u8],
}

impl<'r, 'p> RecordPayload for RawPayload<'r, 'p> {
    fn record_type(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.record_type)
    }

    fn payload(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.payload)
    }
}

mod response {
    use crate::definitions::device_engagement::nfc::{
        ble::{self, ad_packet, AdPacket},
        ndef_parser,
        util::{DisplayBytesAsHex, KnownOrRaw},
    };

    use super::*;

    fn find_record<'a, 'b>(
        records: &'a [ndef_parser::NdefRecord<'b>],
        record_type: RecordType,
    ) -> Result<&'a ndef_parser::NdefRecord<'b>, HandoverError> {
        records
            .iter()
            .find(|r| r.type_bytes == record_type.as_bytes())
            .ok_or_else(|| {
                HandoverError::FailedToFindNdefRecord(record_type, format!("{:?}", records))
            })
    }

    // Service URN for negootiated handover
    const NFC_NEGOTIATED_HANDOVER_SERVICE: &[u8] = b"urn:nfc:sn:handover";

    pub fn initial_tnep_tp() -> Result<Vec<u8>, HandoverError> {
        // See 18013-5 §8.2.2.1 - Device Engagement using NFC
        // See TNEP 1.0 §4.1.2
        let tp_payload = [
            &[
                0x10,                                        // TNEP version 1.0
                NFC_NEGOTIATED_HANDOVER_SERVICE.len() as u8, // Length of service URN
            ],
            NFC_NEGOTIATED_HANDOVER_SERVICE,
            &[
                0x00, // Communication mode: single response
                0x10, // Minimum wait time. TNEP 1.0 §4.1.6
                0x0F, // Maximum no. of time extensions, 0-15. TNEP 1.0 §4.1.7
                NFC_MAX_PAYLOAD_SIZE_BYTES[0],
                NFC_MAX_PAYLOAD_SIZE_BYTES[1],
            ],
        ]
        .concat();
        let tp_record = ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::WellKnown)
            .payload(&RawPayload {
                record_type: RecordType::TnepServiceParameter.as_bytes(),
                payload: &tp_payload,
            })
            .build()
            .map_err(HandoverError::FailedToBuildNdef)?;

        let response_message = ndef_rs::NdefMessage::from(&[tp_record]);
        Ok(response_message
            .to_buffer()
            .map_err(HandoverError::FailedToBuildNdefTypeErased)?)
    }

    pub fn tnep_status(
        ndef_from_reader: &[ndef_parser::NdefRecord],
    ) -> Result<Vec<u8>, HandoverError> {
        let service_select_record = find_record(&ndef_from_reader, RecordType::TnepServiceSelect)?;
        // TODO: Validate service select message
        _ = service_select_record;

        let te_record = ndef_rs::NdefRecord::builder()
            .tnf(ndef_rs::TNF::WellKnown)
            .payload(&RawPayload {
                record_type: RecordType::TnepStatus.as_bytes(),
                payload: &[0x00], // Success
            })
            .build()
            .map_err(HandoverError::FailedToBuildNdef)?;
        let response_message = ndef_rs::NdefMessage::from(&[te_record]);
        Ok(response_message
            .to_buffer()
            .map_err(HandoverError::FailedToBuildNdefTypeErased)?)
    }

    pub fn handover_select(
        ndef_from_reader: &[ndef_parser::NdefRecord],
    ) -> Result<(Vec<u8>, CarrierInfo), HandoverError> {
        let handover_request_record = find_record(ndef_from_reader, RecordType::HandoverRequest)?;
        let hr_payload = handover_request_record.payload;
        if hr_payload.len() < 2 {
            Err(anyhow::anyhow!(
                "Invalid handover request payload: {:?}",
                ndef_from_reader
            ))?;
        }
        let _version = u16::from_le_bytes([hr_payload[0], hr_payload[1]]);
        let hr_embedded_message = &hr_payload[2..];
        let hr_embedded_message = ndef_parser::NdefRecord::iterator_from_bytes(hr_embedded_message);
        let hr_embedded_message = hr_embedded_message
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| HandoverError::InvalidNdef(e, hr_payload[2..].into()))?;

        let mut ret_value: Option<(Vec<u8>, CarrierInfo)> = None;

        for alternative_carrier in hr_embedded_message {
            if alternative_carrier.tnf != ndef_parser::TNF::Media {
                continue;
            }
            if alternative_carrier.type_bytes != b"application/vnd.bluetooth.le.oob" {
                continue;
            }
            let mut psm: Option<u32> = None;
            let mut uuid: Option<uuid::Uuid> = None;
            let mut psm_mac_addr: Option<[u8; 6]> = None;
            {
                let oob_data = alternative_carrier.payload;
                for AdPacket { kind, data } in ble::AdPacket::parse_buffer(oob_data) {
                    let KnownOrRaw::Known(kind) = kind else {
                        continue;
                    };
                    match kind {
                        ad_packet::KnownType::LeRole => {
                            tracing::debug!("LE Role: {data:?}");
                            // TODO: ?
                        }
                        ad_packet::KnownType::PeripheralServerMode => {
                            tracing::debug!("Peripheral Server Mode: {data:?}");
                            let psm_bytes: [u8; 4] = data.try_into().map_err(|_| {
                                anyhow::anyhow!(
                                    "Invalid PSM in OOB data: {}",
                                    DisplayBytesAsHex::from(alternative_carrier.payload)
                                )
                            })?;
                            psm = Some(u32::from_le_bytes(psm_bytes));
                        }
                        ad_packet::KnownType::MacAddress => {
                            tracing::debug!("MAC Address: {data:?}");
                            psm_mac_addr = Some(data.try_into().map_err(|_| {
                                anyhow::anyhow!(
                                    "Invalid MAC Address in OOB data: {}",
                                    DisplayBytesAsHex::from(alternative_carrier.payload)
                                )
                            })?);
                        }
                        ad_packet::KnownType::CompleteList128BitServiceUuids => {
                            let uuids = data
                                .chunks_exact(16)
                                .map(|chunk| {
                                    uuid::Uuid::from_slice(chunk).map_err(|_| {
                                        anyhow::anyhow!(
                                            "Invalid UUID in OOB data: {}",
                                            DisplayBytesAsHex::from(alternative_carrier.payload)
                                        )
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            tracing::debug!("Complete List of 128-bit Service UUIDs: {uuids:?}");
                            let first_uuid = uuids.first().cloned();
                            if let Some(first_uuid) = first_uuid {
                                tracing::debug!("First UUID: {first_uuid:?}");
                                uuid = Some(first_uuid);
                            }
                        }
                    }
                }
            }

            let l2cap = psm == Some(192);
            if let Some(uuid) = uuid {
                tracing::debug!(
                    "Got BLE config: PSM: {psm:?}, UUID: {uuid}, L2CAP: {l2cap}, PSM MAC: {}",
                    psm_mac_addr
                        .map(|mac| format!("{mac:02x?}"))
                        .unwrap_or("None".to_string())
                );
                if ret_value.is_none() {
                    let mut message = vec![1, 5];
                    message.extend_from_slice(
                        &alternative_carrier
                            .to_ndef_rs()?
                            .to_buffer(ndef_rs::RecordFlags::empty())
                            .map_err(|_| {
                                anyhow::anyhow!(
                                    "Failed to encode alternative carrier: {:?}",
                                    alternative_carrier
                                )
                            })?,
                    );
                    ret_value = Some((
                        message,
                        match psm_mac_addr.is_some() && l2cap {
                            true => CarrierInfo::BleL2cap {
                                psm: psm.unwrap_or_default(), // known not empty since l2cap is true if psm == Some(192)
                                uuid,
                                psm_mac_addr,
                            },
                            false => CarrierInfo::Ble { psm, uuid },
                        },
                    ));
                }
            }
        }

        // TODO: Wrong.
        ret_value.ok_or_else(|| {
            anyhow::anyhow!(
                "No valid alternative carrier found in Handover Request: {:?}",
                ndef_from_reader
            )
            .into()
        })
    }
}

#[derive(Debug, Clone)]
pub enum CarrierInfo {
    BleL2cap {
        psm: u32,
        uuid: uuid::Uuid,
        psm_mac_addr: Option<[u8; 6]>, // TODO: Is this actually optional?
    },
    Ble {
        psm: Option<u32>, // TODO: Is this actually optional?
        uuid: uuid::Uuid,
    },
}

impl CarrierInfo {
    pub fn uuid(&self) -> uuid::Uuid {
        match self {
            CarrierInfo::BleL2cap { uuid, .. } => *uuid,
            CarrierInfo::Ble { uuid, .. } => *uuid,
        }
    }
}

pub struct HandoverResponse {
    pub new_state: HandoverState,
    pub ndef: Vec<u8>,
}

pub fn get_handover_ndef_response(
    state: &HandoverState,
    ndef_bytes_from_reader: &[u8],
) -> Result<HandoverResponse, HandoverError> {
    let ndef_from_reader = match ndef_bytes_from_reader.is_empty() {
        true => None,
        false => Some(
            ndef_parser::NdefRecord::iterator_from_bytes(ndef_bytes_from_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| HandoverError::InvalidNdef(e, ndef_bytes_from_reader.into()))?,
        ),
    };
    tracing::debug!("recv NDEF: {:?}", ndef_from_reader);
    use HandoverState::*;
    let ret = match state {
        Init => {
            if ndef_from_reader.is_some() {
                return Err(HandoverError::UnexpectedNdef(
                    ndef_bytes_from_reader.to_owned(),
                ));
            }
            HandoverResponse {
                ndef: response::initial_tnep_tp()?,
                new_state: WaitingForServiceSelect,
            }
        }
        WaitingForServiceSelect => {
            let ndef_from_reader = ndef_from_reader.ok_or(HandoverError::MissingNdef)?;
            HandoverResponse {
                ndef: response::tnep_status(&ndef_from_reader)?,
                new_state: WaitingForHandoverRequest,
            }
        }
        WaitingForHandoverRequest => {
            let ndef_from_reader = ndef_from_reader.ok_or(HandoverError::MissingNdef)?;
            let ret_value = response::handover_select(&ndef_from_reader)?;
            HandoverResponse {
                ndef: ret_value.0,
                new_state: Done(ret_value.1),
            }
        }
        Done(ci) => {
            return Err(HandoverError::UnexpectedState {
                state: Done(ci.clone()),
                location: "get_handover_ndef_response".to_string(),
            });
        }
    };
    tracing::debug!(
        "send NDEF (raw): {:?}",
        DisplayBytesAsHex::from(ret.ndef.as_slice())
    );
    // tracing::debug!(
    //     "send NDEF: {:?}",
    //     ndef_parser::NdefRecord::iterator_from_bytes(&ret.ndef)
    //         .collect::<Result<Vec<_>, _>>()
    //         .unwrap()
    // );
    Ok(ret)
}
