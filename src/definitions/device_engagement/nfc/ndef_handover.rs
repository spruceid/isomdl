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
