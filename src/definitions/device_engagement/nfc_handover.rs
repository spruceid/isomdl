use std::borrow::Cow;

use ndef_rs::{
    self as ndef,
    payload::{RecordPayload, UriPayload},
    NdefMessage, NdefRecord,
};
use serde::{Deserialize, Serialize};

use super::{DeviceEngagement, DeviceRetrievalMethod};
use crate::definitions::session::Error;
use crate::definitions::{
    device_engagement::CentralClientMode,
    helpers::{ByteStr, Tag24},
};

/// When negotiated handover is used, the mdoc (holder) should include
/// the following service URN to the reader, which will be used to select
/// the appropriate alternative carrier record in a handover request message.
///
/// See 18013-5 §8.2.2.1 Device Engagement using NFC for more information.
pub const NFC_NEGOTIATED_HANDOVER_SERVICE: &str = "urn:nfc:sn:handover";
pub const TNF_WELL_KNOWN: u8 = 0x01;
pub const TNF_MIME_MEDIA: u8 = 0x02;

pub type NfcHandoverSelectMessage = ByteStr;
pub type NfcHandoverRequestMessage = Option<ByteStr>;

// ndef_rs provides ExternalPayload, but this seems to have semantic meaning.
// We'll implement our own form of it with no implied semantics.
// This also allows us to use local borrows (since ExternalPayload only uses 'static),
// preventing unnecessary copies :)
#[derive(Debug, Clone)]
struct RawPayload<'r, 'p> {
    record_type: &'r [u8],
    payload: &'p [u8],
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
pub struct NfcHandover(pub NfcHandoverSelectMessage, pub NfcHandoverRequestMessage);

impl NfcHandover {
    pub fn create_direct_handover() -> Result<Self, Error> {
        let tp_payload = [
            &[
                0x10,                                        // TNEP version 1.0
                NFC_NEGOTIATED_HANDOVER_SERVICE.len() as u8, // Length of service URN
            ],
            NFC_NEGOTIATED_HANDOVER_SERVICE.as_bytes(),
            &[
                0x00, // Single response communication mode
                0x10, // Minimum wait time. TODO: magic number
                0x0F, // Maximum no. of time extensions. TODO: magic number
                0xFF, // Max NDEF size (upper bits)
                0xFF, // Max NDEF size (lower bits)
            ],
        ]
        .concat();

        // Create the Tp (Transport Protocol) record
        let tp_record = NdefMessage::from(&[NdefRecord::builder()
            .tnf(ndef::TNF::WellKnown)
            .payload(&RawPayload {
                record_type: b"Tp",
                payload: &tp_payload,
            })
            .build()?]);

        // Final top-level NDEF message
        Ok(NfcHandover(
            tp_record
                .to_buffer()
                .map_err(Error::NdefSerialization)?
                .into(),
            None,
        ))
    }

    pub fn create_handover_select(
        device_engagement: &Tag24<DeviceEngagement>,
        nfc_handover_request: NfcHandoverRequestMessage,
    ) -> Result<Self, Error> {
        let uri_record = NdefRecord::builder()
            .tnf(ndef::TNF::WellKnown)
            .payload(&UriPayload::static_with_abbrev(
                ndef::NONE_ABBRE,
                NFC_NEGOTIATED_HANDOVER_SERVICE,
            ))
            .build()?;

        let mut message = NdefMessage::from(&[uri_record]);

        // Dynamic AC/Carrier records
        if let Some(retrieval_methods) = device_engagement.inner.device_retrieval_methods.as_ref() {
            for method in retrieval_methods.iter() {
                if let DeviceRetrievalMethod::BLE(options) = method {
                    if let Some(CentralClientMode { uuid }) = options.central_client_mode.as_ref() {
                        // TODO: Do we want to be completely ignoring the reported method?
                        const CARRIER_DATA_REFERENCE_ID: u8 = b'B';

                        let ac_record = NdefRecord::builder()
                            .tnf(ndef::TNF::WellKnown)
                            .payload(&RawPayload {
                                record_type: b"ac",
                                payload: &[
                                    0x01, // Carrier Power State: active
                                    0x01, // Length of Carrier Data Reference
                                    CARRIER_DATA_REFERENCE_ID,
                                    0x00, // Auxiliary Data Reference Count
                                ],
                            })
                            .build()?;

                        let bt_record = NdefRecord::builder()
                            .tnf(ndef::TNF::MimeMedia)
                            .payload(&RawPayload {
                                record_type: b"application/vnd.bluetooth.ep.oob",
                                payload: &[
                                    [
                                        0x02, // Length of LE Role Payload
                                        0x1C, // LE Role Advertising Data Type
                                        0x01, // Central Client Mode BLE role
                                        // Following represents the service UUIDs
                                        0x11, 0x07,
                                    ]
                                    .as_slice(),
                                    uuid.as_bytes(),
                                ]
                                .concat(),
                            })
                            .id(vec![CARRIER_DATA_REFERENCE_ID]) // must match AC reference
                            .build()?;

                        message.add_record(ac_record);
                        message.add_record(bt_record);
                    }
                }
            }
        }

        let mut hs_payload = vec![0x12]; // Version 1.2
        hs_payload.extend_from_slice(&message.to_buffer().map_err(Error::NdefSerialization)?);

        let hs_record = NdefMessage::from(&[NdefRecord::builder()
            .tnf(ndef::TNF::WellKnown)
            .payload(&RawPayload {
                record_type: b"Hs",
                payload: &hs_payload,
            })
            .build()?]);

        // Final top-level NDEF message
        Ok(NfcHandover(
            hs_record
                .to_buffer()
                .map_err(Error::NdefSerialization)?
                .into(),
            nfc_handover_request,
        ))
    }
}
