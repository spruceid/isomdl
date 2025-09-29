use std::borrow::Cow;

use ndef_rs::{payload::RecordPayload, NdefRecord};
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::definitions::{
    device_engagement::nfc::{
        ble, ndef_parser,
        util::{ByteVecDisplayAsHex, DisplayBytesAsHex},
        StaticHandoverState,
    },
    helpers::ByteStr,
    traits::ToCbor,
    DeviceEngagement,
};

pub(super) const NFC_MAX_PAYLOAD_SIZE: usize = 255 - 2; // 255 minus 2 bytes for the u16 size at the beginning of the payload
pub(super) const NFC_MAX_PAYLOAD_SIZE_BYTES: [u8; 2] = (NFC_MAX_PAYLOAD_SIZE as u16).to_be_bytes();

#[derive(Debug, Clone)]
pub enum HandoverState {
    Init,
    WaitingForServiceSelect,
    WaitingForHandoverRequest,
    Done(Box<NegotiatedCarrierInfo>),
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
        state: Box<HandoverState>,
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
        RecordType::iter().find(|&record_type| record_type.as_bytes() == bytes)
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

const TNEP_MIN_WAIT_TIME: u8 = 0x09;
const TNEP_MAX_TIME_EXTENSIONS: u8 = 0x05;

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
                HandoverError::FailedToFindNdefRecord(record_type, format!("{records:?}"))
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
                0x00,                     // Communication mode: single response
                TNEP_MIN_WAIT_TIME,       // Minimum wait time. TNEP 1.0 §4.1.6
                TNEP_MAX_TIME_EXTENSIONS, // Maximum no. of time extensions, 0-15. TNEP 1.0 §4.1.7
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
        response_message
            .to_buffer()
            .map_err(HandoverError::FailedToBuildNdefTypeErased)
    }

    pub fn tnep_status(
        ndef_from_reader: &[ndef_parser::NdefRecord],
    ) -> Result<Vec<u8>, HandoverError> {
        let service_select_record = find_record(ndef_from_reader, RecordType::TnepServiceSelect)?;
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
        response_message
            .to_buffer()
            .map_err(HandoverError::FailedToBuildNdefTypeErased)
    }

    pub fn handover_select(
        ndef_from_reader: &[ndef_parser::NdefRecord],
    ) -> Result<(Vec<u8>, NegotiatedCarrierInfo), HandoverError> {
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

        let mut ret_value: Option<(Vec<u8>, NegotiatedCarrierInfo)> = None;

        for alternative_carrier in hr_embedded_message {
            if alternative_carrier.tnf != ndef_parser::Tnf::Media {
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
                    /*
                    ret_value = Some((
                        message,
                        CarrierInfo {
                            uuid,
                            ble: match psm_mac_addr.is_some() && l2cap {
                                true => BleInfo::L2cap {
                                    psm: psm.unwrap_or_default(), // known not empty since l2cap is true if psm == Some(192)
                                    psm_mac_addr,
                                },
                                false => BleInfo::NotL2cap { psm },
                            },
                        },
                    ));
                    */
                    todo!("negotiated handover");
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
pub enum BleInfo {
    L2cap {
        psm: u32,
        psm_mac_addr: Option<[u8; 6]>, // TODO: Is this actually optional?
    },
    NotL2cap {
        psm: Option<u32>, // TODO: Is this actually optional?
    },
    StaticHandover {
        private_key: Vec<u8>,
        device_engagement: Box<DeviceEngagement>,
    },
}

#[derive(Debug, Clone)]
pub struct NegotiatedCarrierInfo {
    pub ble: BleInfo,
    pub uuid: uuid::Uuid,
    pub hs_message: ByteStr,
    pub hr_message: Option<ByteStr>,
}

pub struct HandoverResponse {
    pub new_state: HandoverState,
    pub ndef: Vec<u8>,
}

pub fn get_static_handover_ndef_response(
    static_handover_state: StaticHandoverState,
) -> Result<HandoverResponse, HandoverError> {
    // TODO: I feel like this logic should maybe not live in crate::definitions?
    let StaticHandoverState {
        uuid,
        private_key,
        security,
    } = static_handover_state;

    tracing::info!("Static handover with UUID: {}", uuid);

    let device_engagement = DeviceEngagement {
        version: "1.0".into(),
        security,
        device_retrieval_methods: None,
        protocol_info: None,
        server_retrieval_methods: None,
    };

    const MDOC_ID: &[u8] = b"mdoc";

    let device_engagement_record = ndef_rs::NdefRecord::builder()
        .tnf(ndef_rs::TNF::External)
        .id(MDOC_ID.into())
        .payload(&RawPayload {
            record_type: b"iso.org:18013:deviceengagement",
            payload: &device_engagement
                .clone()
                .to_cbor_bytes()
                .map_err(|e| anyhow::anyhow!("Failed to generate device engagement record: {e}"))?,
        })
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build device engagement record: {e}"))?;

    use ble::ad_packet::KnownType as BleTypeByte;
    let (ac_record, cc_record) = {
        const OOB_RECORD_ID: &[u8] = b"0";

        let ac_record = NdefRecord::builder()
            .tnf(ndef_rs::TNF::WellKnown)
            .payload(&RawPayload {
                record_type: b"ac",
                payload: &[
                    [
                        0x01,                      // Carrier Power State: active
                        OOB_RECORD_ID.len() as u8, // Length of Carrier Data Reference
                    ]
                    .as_slice(),
                    OOB_RECORD_ID,
                    [
                        0x01, // Auxiliary Data Reference Count
                        MDOC_ID.len() as u8,
                    ]
                    .as_slice(),
                    MDOC_ID,
                ]
                .concat(),
            })
            .build()
            .map_err(|e| {
                anyhow::anyhow!("Failed to create central client mode NDEF record: {e}")
            })?;

        let mut uuid_bytes = *uuid.as_bytes();
        uuid_bytes.reverse();
        let ble_oob_payload = [
            [
                0x02, // Length of LE Role Payload
                BleTypeByte::LeRole as u8,
                0x01, // Central Client Mode BLE role
                0x11, // Length of UUID payload
                BleTypeByte::CompleteList128BitServiceUuids as u8,
            ]
            .as_slice(),
            &uuid_bytes,
        ]
        .concat();

        let ble_oob_record = NdefRecord::builder()
            .id(OOB_RECORD_ID.into())
            .tnf(ndef_rs::TNF::MimeMedia)
            .payload(&RawPayload {
                record_type: b"application/vnd.bluetooth.le.oob",
                payload: &ble_oob_payload,
            })
            .build()
            .map_err(|e| {
                anyhow::anyhow!("Failed to create central client mode NDEF record: {e}")
            })?;

        (ac_record, ble_oob_record)
    };

    let hs_payload = [
        [0x15].as_slice(), // Version
        &ndef_rs::NdefMessage::from(ac_record)
            .to_buffer()
            .map_err(|e| anyhow::anyhow!("Failed to construct handover select payload: {e}"))?,
    ]
    .concat();

    let hs_record = ndef_rs::NdefRecord::builder()
        .tnf(ndef_rs::TNF::WellKnown)
        .payload(&RawPayload {
            record_type: RecordType::HandoverSelect.as_bytes(),
            payload: &hs_payload,
        })
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create handover select NDEF record: {e}"))?;

    let response = ndef_rs::NdefMessage::from([hs_record, device_engagement_record, cc_record])
        .to_buffer()
        .map_err(|e| anyhow::anyhow!("Failed to construct NDEF message: {e}"))?;

    let state = HandoverState::Done(Box::new(NegotiatedCarrierInfo {
        uuid,
        ble: BleInfo::StaticHandover {
            private_key,
            device_engagement: Box::new(device_engagement),
        },
        hs_message: ByteStr::from(response.clone()),
        hr_message: None,
    }));

    Ok(HandoverResponse {
        new_state: state,
        ndef: response,
    })
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
                new_state: Done(ret_value.1.into()),
            }
        }
        Done(ci) => {
            return Err(HandoverError::UnexpectedState {
                state: Done(ci.clone()).into(),
                location: "get_handover_ndef_response".to_string(),
            });
        }
    };
    tracing::debug!(
        "send NDEF (raw): {:?}",
        DisplayBytesAsHex::from(ret.ndef.as_slice())
    );
    tracing::debug!(
        "send NDEF: {:?}",
        ndef_parser::NdefRecord::iterator_from_bytes(&ret.ndef)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    );
    Ok(ret)
}
