use serde::{Deserialize, Serialize};

use super::{DeviceEngagement, DeviceRetrievalMethod};
use crate::definitions::helpers::{ByteStr, Tag24};
use crate::definitions::session::Error;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfcHandover(pub NfcHandoverSelectMessage, pub NfcHandoverRequestMessage);

impl NfcHandover {
    pub fn create_handover_select(
        device_engagement: &Tag24<DeviceEngagement>,
        nfc_handover_request: NfcHandoverRequestMessage,
    ) -> Result<Self, Error> {
        let mut embedded_ndef = Vec::new();

        // Track how many records total we will emit
        let mut record_parts = Vec::new();

        // URI Record for negotiated handover support (urn:nfc:sn:handover)
        let uri_record = NdefRecord {
            tnf: TNF_WELL_KNOWN,
            type_field: vec![b'U'], // URI Record type
            id: None,
            payload: {
                let mut payload = vec![0x00]; // URI Identifier Code 0x00 = no prefix
                payload.extend_from_slice(NFC_NEGOTIATED_HANDOVER_SERVICE.as_bytes());
                payload
            },
        };

        // URI record
        record_parts.push(uri_record);

        // Dynamic AC/Carrier records
        if let Some(retrieval_methods) = device_engagement.inner.device_retrieval_methods.as_ref() {
            for method in retrieval_methods.iter() {
                if let DeviceRetrievalMethod::BLE(_) = method {
                    let (ac_record, bt_record) =
                        NdefRecord::configure_bluetooth_alternative_carrier_records(
                            device_engagement,
                        )?;
                    record_parts.push(ac_record);
                    record_parts.push(bt_record);
                }
            }
        }

        // Encode records with Message Beginning (MB)/Message Ending (ME) flags
        for (i, record) in record_parts.iter().enumerate() {
            let mb = i == 0;
            let me = i == record_parts.len() - 1;
            embedded_ndef.extend_from_slice(&record.encode(mb, me));
        }

        let mut hs_payload = vec![0x12]; // Version 1.2
        hs_payload.extend_from_slice(&embedded_ndef);

        let hs_record = NdefRecord {
            tnf: TNF_WELL_KNOWN,
            type_field: b"Hs".to_vec(),
            id: None,
            payload: hs_payload,
        };

        // Final top-level NDEF message
        Ok(NfcHandover(
            hs_record.encode(true, true).into(),
            nfc_handover_request,
        ))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NdefRecord {
    pub tnf: u8,
    pub type_field: Vec<u8>,
    pub id: Option<Vec<u8>>,
    pub payload: Vec<u8>,
}

impl NdefRecord {
    /// Create alternative carrier records for bluetooth handover.
    fn configure_bluetooth_alternative_carrier_records(
        device_engagement: &Tag24<DeviceEngagement>,
    ) -> Result<(Self, Self), Error> {
        Ok((
            NdefRecord {
                tnf: TNF_WELL_KNOWN,
                type_field: b"ac".to_vec(),
                id: None,
                payload: vec![
                    0x01, // Carrier Power State: active
                    0x01, // Length of Carrier Data Reference
                    b'B', // Carrier Data Reference ID
                    0x00, // Auxiliary Data Reference Count
                ],
            },
            NdefRecord {
                tnf: TNF_MIME_MEDIA,
                type_field: b"application/vnd.bluetooth.ep.oob".to_vec(),
                id: Some(b"B".to_vec()), // must match AC reference
                payload: device_engagement.inner_bytes.clone(),
            },
        ))
    }

    /// `mb` -> message begin
    /// `me` -> message end
    ///
    /// Encodes the NDEF record into a byte vector.
    pub fn encode(&self, mb: bool, me: bool) -> Vec<u8> {
        let sr = self.payload.len() < 256;
        let il = self.id.is_some();
        let mut header = 0;
        if mb {
            header |= 0x80;
        }
        if me {
            header |= 0x40;
        }
        if sr {
            header |= 0x10;
        }
        if il {
            header |= 0x08;
        }
        header |= self.tnf & 0x07;

        let mut record = vec![header];
        record.push(self.type_field.len() as u8);

        if sr {
            record.push(self.payload.len() as u8);
        } else {
            record.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        }

        if il {
            record.push(self.id.as_ref().unwrap().len() as u8);
        }

        record.extend_from_slice(&self.type_field);
        if il {
            record.extend_from_slice(self.id.as_ref().unwrap());
        }
        record.extend_from_slice(&self.payload);
        record
    }
}
