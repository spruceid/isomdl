use std::borrow::Cow;

use ndef_rs::{payload::RecordPayload, NdefRecord};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::definitions::{
    device_engagement::nfc::{ble, ndef_parser, util::ByteVecDisplayAsHex, StaticHandoverState},
    helpers::ByteStr,
    traits::ToCbor,
    DeviceEngagement,
};

pub(super) const TNEP_HANDOVER_SERVICE_URI: &str = "urn:nfc:sn:handover";

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

#[repr(u8)]
#[rustfmt::skip]
#[derive(strum_macros::FromRepr, Debug, Clone, Copy, Serialize, Deserialize)]
/// The LE Role data type defines the LE role capabilities of the device.
pub enum LeRole {
    /// Only Peripheral Role supported
    PeripheralOnly = 0x00,
    /// Only Central Role supported
    CentralOnly = 0x01,
    /// Peripheral and Central Role supported, Peripheral Role preferred for connection establishment
    PeripheralPreferred = 0x02,
    /// Peripheral and Central Role supported, Central Role preferred for connection establishment
    CentralPreferred = 0x03,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BleInfo {
    StaticHandover {
        private_key: Vec<u8>,
        device_engagement: Box<DeviceEngagement>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiatedCarrierInfo {
    pub ble: BleInfo,
    pub uuid: uuid::Uuid,
    /// Handover Select Message
    pub hs_message: ByteStr,
    /// Handover Request Message
    pub hr_message: Option<ByteStr>,
}

pub struct HandoverResponse {
    pub new_state: HandoverState,
    pub ndef: Vec<u8>,
}

fn build_hs_ndef(
    static_state: StaticHandoverState,
    hr_message: Option<ByteStr>,
) -> Result<(Vec<u8>, NegotiatedCarrierInfo), HandoverError> {
    // TODO: I feel like this logic should maybe not live in crate::definitions?
    let StaticHandoverState {
        uuid,
        private_key,
        security,
    } = static_state;

    tracing::info!("Handover with UUID: {}", uuid);

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
                LeRole::CentralOnly as u8, // Central Client Mode BLE role
                0x11,                      // Length of UUID payload
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

    let hs_ndef = ndef_rs::NdefMessage::from([hs_record, device_engagement_record, cc_record])
        .to_buffer()
        .map_err(|e| anyhow::anyhow!("Failed to construct NDEF message: {e}"))?;

    let carrier_info = NegotiatedCarrierInfo {
        uuid,
        ble: BleInfo::StaticHandover {
            private_key,
            device_engagement: Box::new(device_engagement),
        },
        hs_message: ByteStr::from(hs_ndef.clone()),
        hr_message,
    };

    Ok((hs_ndef, carrier_info))
}

pub fn get_static_handover_ndef_response(
    static_state: StaticHandoverState,
) -> Result<HandoverResponse, HandoverError> {
    let (ndef, carrier_info) = build_hs_ndef(static_state, None)?;
    Ok(HandoverResponse {
        new_state: HandoverState::Done(Box::new(carrier_info)),
        ndef,
    })
}

pub(super) fn generate_tp_ndef() -> Result<Vec<u8>, HandoverError> {
    let uri_bytes = TNEP_HANDOVER_SERVICE_URI.as_bytes();
    let payload = [
        &[0x10u8, uri_bytes.len() as u8] as &[u8],
        uri_bytes,
        &[0x00, 0x0F, 0xFF, 0xFF],
    ]
    .concat();
    let tp_record = ndef_rs::NdefRecord::builder()
        .tnf(ndef_rs::TNF::WellKnown)
        .payload(&RawPayload {
            record_type: RecordType::TnepServiceParameter.as_bytes(),
            payload: &payload,
        })
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build Tp NDEF record: {e}"))?;
    ndef_rs::NdefMessage::from(tp_record)
        .to_buffer()
        .map_err(|e| anyhow::anyhow!("Failed to build Tp NDEF message: {e}").into())
}

pub(super) fn get_negotiated_tp_ndef_response() -> Result<HandoverResponse, HandoverError> {
    Ok(HandoverResponse {
        new_state: HandoverState::WaitingForServiceSelect,
        ndef: generate_tp_ndef()?,
    })
}

pub(super) fn handle_ts_write(data: &[u8]) -> Result<HandoverResponse, HandoverError> {
    let ts_ndef = data.get(2..).ok_or_else(|| {
        anyhow::anyhow!("Ts UPDATE BINARY payload too short ({} bytes)", data.len())
    })?;
    let message = ndef_rs::NdefMessage::decode(ts_ndef)
        .map_err(|e| anyhow::anyhow!("Failed to decode Ts NDEF: {e}"))?;
    let ts_record = message
        .records()
        .iter()
        .find(|r| r.record_type() == RecordType::TnepServiceSelect.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("No Ts record found in UPDATE BINARY payload"))?;
    let payload = ts_record.payload();
    let uri_len = *payload
        .first()
        .ok_or_else(|| anyhow::anyhow!("Ts record has empty payload"))? as usize;
    let uri_bytes = payload.get(1..1 + uri_len).ok_or_else(|| {
        anyhow::anyhow!("Ts record payload too short for declared URI length {uri_len}")
    })?;
    let uri = std::str::from_utf8(uri_bytes)
        .map_err(|e| anyhow::anyhow!("Ts URI is not valid UTF-8: {e}"))?;
    if uri != TNEP_HANDOVER_SERVICE_URI {
        return Err(anyhow::anyhow!(
            "Ts selected unknown service URI: {uri:?} (expected {TNEP_HANDOVER_SERVICE_URI:?})"
        )
        .into());
    }

    let te_record = ndef_rs::NdefRecord::builder()
        .tnf(ndef_rs::TNF::WellKnown)
        .payload(&RawPayload {
            record_type: RecordType::TnepStatus.as_bytes(),
            payload: &[0x00],
        })
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build Te NDEF record: {e}"))?;
    let te_ndef = ndef_rs::NdefMessage::from(te_record)
        .to_buffer()
        .map_err(|e| anyhow::anyhow!("Failed to build Te NDEF message: {e}"))?;

    Ok(HandoverResponse {
        new_state: HandoverState::WaitingForHandoverRequest,
        ndef: te_ndef,
    })
}

pub(super) fn handle_hr_write(
    data: &[u8],
    static_state: StaticHandoverState,
) -> Result<HandoverResponse, HandoverError> {
    let hr_ndef_bytes = data.get(2..).ok_or_else(|| {
        anyhow::anyhow!("Hr UPDATE BINARY payload too short ({} bytes)", data.len())
    })?;
    let hr_message = ByteStr::from(hr_ndef_bytes.to_vec());
    let (hs_ndef, carrier_info) = build_hs_ndef(static_state, Some(hr_message))?;
    Ok(HandoverResponse {
        new_state: HandoverState::Done(Box::new(carrier_info)),
        ndef: hs_ndef,
    })
}
