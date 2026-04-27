// The base specs for this are Bluetooth® Secure Simple Pairing Using NFC, with some bits coming
// from ISO 7816-4 and ISO 18013-5.

use anyhow::{anyhow, bail, Context, Result};
use ndef_rs::{NdefRecord, TNF};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    cbor,
    definitions::{
        device_engagement::nfc::{
            ble::ad_packet::KnownType,
            ndef_handover::{LeRole, RawPayload, RecordType},
        },
        helpers::ByteStr,
        DeviceEngagement,
    },
};

pub(super) const TNEP_HANDOVER_SERVICE_URI: &str = "urn:nfc:sn:handover";

#[derive(Debug, Clone)]
pub enum ReaderHandoverState {
    WaitingForAidResponse,
    WaitingForCapabilitiesFileResponse,
    WaitingForCapabilitiesReadResponse,
    WaitingForNdefFileResponse,
    WaitingForNdefReadResponseLength,
    WaitingForNdefReadResponseData {
        total_length: usize,
        data: Vec<u8>,
    },
    // Negotiated handover states
    WaitingForTsWriteResponse,
    WaitingForTeLength,
    WaitingForTeData {
        total_length: usize,
        data: Vec<u8>,
    },
    WaitingForHrWriteResponse {
        hr_bytes: Vec<u8>,
        hr_uuid: Uuid,
    },
    WaitingForHsLength {
        hr_bytes: Vec<u8>,
        hr_uuid: Uuid,
    },
    WaitingForHsData {
        total_length: usize,
        data: Vec<u8>,
        hr_bytes: Vec<u8>,
        hr_uuid: Uuid,
    },
    Done,
}

/// Returns the TNEP service URI if the NDEF data contains a Well-Known "Tp" (Service Parameter) record.
pub(super) fn detect_tp_service(data: &[u8]) -> Option<String> {
    let message = ndef_rs::NdefMessage::decode(data).ok()?;
    let record = message
        .records()
        .iter()
        .find(|r| r.record_type() == b"Tp" && r.tnf() == TNF::WellKnown)?;
    // Tp payload: [tnep_version (1)][service_name_length (1)][service_name]...
    let payload = record.payload();
    if payload.len() < 2 {
        return None;
    }
    let name_len = payload[1] as usize;
    if payload.len() < 2 + name_len {
        return None;
    }
    String::from_utf8(payload[2..2 + name_len].to_vec()).ok()
}

/// Builds the TNEP Service Select (Ts) NDEF message for the given service URI.
/// Returns raw NDEF bytes (without the 2-byte length prefix used in APDUs).
pub(super) fn generate_ts_ndef(service_uri: &str) -> Result<Vec<u8>> {
    let uri_bytes = service_uri.as_bytes();
    let payload = [[uri_bytes.len() as u8].as_slice(), uri_bytes].concat();
    let ts_record = NdefRecord::builder()
        .tnf(TNF::WellKnown)
        .payload(&RawPayload {
            record_type: b"Ts",
            payload: &payload,
        })
        .build()
        .map_err(|e| anyhow!("Failed to build Ts NDEF record: {e}"))?;
    ndef_rs::NdefMessage::from(ts_record)
        .to_buffer()
        .map_err(|e| anyhow!("Failed to build Ts NDEF message: {e}"))
}

/// Builds the Handover Request (Hr) NDEF message for BLE + NFC carriers.
/// Returns (raw NDEF bytes, reader UUID used in the BLE OOB record).
pub(super) fn generate_hr_ndef() -> Result<(Vec<u8>, Uuid)> {
    let uuid = Uuid::new_v4();
    let mut uuid_bytes = *uuid.as_bytes();
    uuid_bytes.reverse(); // big-endian to little-endian for BLE OOB

    // Embedded NDEF inside Hr payload: two Alternative Carrier records
    let ble_ac_record = NdefRecord::builder()
        .tnf(TNF::WellKnown)
        .payload(&RawPayload {
            record_type: b"ac",
            payload: &[
                0x01, // carrier power state: active
                0x01, // carrier data reference length: 1
                b'0', // carrier data reference: "0"
                0x00, // auxiliary data reference count: 0
            ],
        })
        .build()
        .map_err(|e| anyhow!("Failed to build BLE ac record: {e}"))?;

    let nfc_ac_record = NdefRecord::builder()
        .tnf(TNF::WellKnown)
        .payload(&RawPayload {
            record_type: b"ac",
            payload: &[
                0x01, // carrier power state: active
                0x03, // carrier data reference length: 3
                b'n', b'f', b'c', // carrier data reference: "nfc"
                0x00, // auxiliary data reference count: 0
            ],
        })
        .build()
        .map_err(|e| anyhow!("Failed to build NFC ac record: {e}"))?;

    let embedded_ndef = ndef_rs::NdefMessage::from([ble_ac_record, nfc_ac_record])
        .to_buffer()
        .map_err(|e| anyhow!("Failed to build Hr embedded NDEF: {e}"))?;

    let hr_payload = [[0x15u8].as_slice(), &embedded_ndef].concat(); // version 1.5

    let hr_record = NdefRecord::builder()
        .tnf(TNF::WellKnown)
        .payload(&RawPayload {
            record_type: b"Hr",
            payload: &hr_payload,
        })
        .build()
        .map_err(|e| anyhow!("Failed to build Hr record: {e}"))?;

    // ReaderEngagement CBOR: {0: "1.0"} = a1 00 63 31 2e 30
    const READER_ENGAGEMENT_CBOR: &[u8] = &[0xa1, 0x00, 0x63, 0x31, 0x2e, 0x30];
    let reader_engagement_record = NdefRecord::builder()
        .tnf(TNF::External)
        .id(b"mdocreader".to_vec())
        .payload(&RawPayload {
            record_type: b"iso.org:18013:readerengagement",
            payload: READER_ENGAGEMENT_CBOR,
        })
        .build()
        .map_err(|e| anyhow!("Failed to build ReaderEngagement record: {e}"))?;

    // BLE LE OOB: LE Role (CentralPreferred) + 128-bit UUID
    let ble_oob_payload = [
        [
            0x02, // length=2 (type + value)
            0x1c, // type: LE Role
            0x03, // CentralPreferred
            0x11, // length=17 (type + 16-byte UUID)
            0x07, // type: Complete List 128-bit UUIDs
        ]
        .as_slice(),
        &uuid_bytes,
    ]
    .concat();

    let ble_oob_record = NdefRecord::builder()
        .tnf(TNF::MimeMedia)
        .id(b"0".to_vec())
        .payload(&RawPayload {
            record_type: b"application/vnd.bluetooth.le.oob",
            payload: &ble_oob_payload,
        })
        .build()
        .map_err(|e| anyhow!("Failed to build BLE OOB record: {e}"))?;

    // NFC Carrier Config: per ISO 18013-5 §8.2.2.2 Table 6.
    // The max cmd/rsp fields are conditional and "shall not be used by the mdoc reader" per spec,
    // but Google Wallet (and possibly other implementations) parse all 6 bytes unconditionally,
    // crashing with BufferUnderflowException if only the 1-byte version is present.
    // Include the full payload as an interop workaround.
    //   [0x01]              version
    //   [0x01, 0xFF]        max cmd data field: length=1, value=255 (spec minimum)
    //   [0x02, 0xFF, 0xFF]  max rsp data field: length=2, value=65535
    let nfc_config_record = NdefRecord::builder()
        .tnf(TNF::External)
        .id(b"nfc".to_vec())
        .payload(&RawPayload {
            record_type: b"iso.org:18013:nfc",
            payload: &[0x01, 0x01, 0xFF, 0x02, 0xFF, 0xFF],
        })
        .build()
        .map_err(|e| anyhow!("Failed to build NFC config record: {e}"))?;

    let hr_ndef = ndef_rs::NdefMessage::from(vec![
        hr_record,
        reader_engagement_record,
        ble_oob_record,
        nfc_config_record,
    ])
    .to_buffer()
    .map_err(|e| anyhow!("Failed to build Hr NDEF message: {e}"))?;

    Ok((hr_ndef, uuid))
}

/// Parses a TNEP Status (Te) NDEF message and returns Ok if status is success (0x00).
pub(super) fn parse_te_ndef(data: &[u8]) -> Result<()> {
    let message =
        ndef_rs::NdefMessage::decode(data).map_err(|e| anyhow!("Failed to decode Te NDEF: {e}"))?;
    let record = message
        .records()
        .iter()
        .find(|r| r.record_type() == b"Te" && r.tnf() == TNF::WellKnown)
        .ok_or_else(|| anyhow!("No TNEP Status (Te) record found in NDEF message"))?;
    let status = record
        .payload()
        .first()
        .ok_or_else(|| anyhow!("Te record has empty payload"))?;
    if *status != 0x00 {
        bail!("TNEP status error: {status:#x}");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaderNegotiatedCarrierInfo {
    pub device_engagement: DeviceEngagement,
    pub uuid: Uuid,
    pub holder_le_role: LeRole,
    /// Handover Select Message
    pub hs_message: ByteStr,
    /// Handover Request Message
    pub hr_message: Option<ByteStr>,
    pub ble_device_address: Option<ByteStr>,
}

impl ReaderNegotiatedCarrierInfo {
    pub fn parse_ndef_message(ndef_response: &[u8]) -> Result<Self, anyhow::Error> {
        let hs_message = ByteStr::from(ndef_response.to_vec());
        let ndef_message =
            ndef_rs::NdefMessage::decode(ndef_response).context("Failed to decode ndef message")?;
        let ndef_records = ndef_message.records();

        match ndef_records.iter().find(|r| {
            r.record_type() == RecordType::TnepServiceParameter.as_bytes()
                && r.tnf() == TNF::WellKnown
        }) {
            None => Self::parse_ndef_records(hs_message, ndef_records, None)
                .context("Failed to parse static handover NDEF message"),
            Some(_) => bail!("negotiated handover not supported"),
        }
    }

    /// Parse the Handover Select NDEF message received during negotiated handover.
    ///
    /// Per ISO 18013-5 §8.3.3.1.1.2, the mdoc is only required to include a UUID in the Hs when
    /// it chooses mdoc peripheral server mode. When the mdoc selects central client mode (LE
    /// Role=0x01 "Only Central"), it omits the UUID from the Hs because it will connect as Central
    /// using the UUID the reader sent in the Hr. In that case `hr_uuid` is used as the UUID for
    /// the Peripheral advertisement that the reader broadcasts (§8.3.3.1.1.3).
    pub(super) fn parse_hs_ndef_message(
        ndef_response: &[u8],
        hr_uuid: Uuid,
    ) -> Result<Self, anyhow::Error> {
        let hs_message = ByteStr::from(ndef_response.to_vec());
        let ndef_message =
            ndef_rs::NdefMessage::decode(ndef_response).context("Failed to decode ndef message")?;
        let ndef_records = ndef_message.records();
        Self::parse_ndef_records(hs_message, ndef_records, Some(hr_uuid))
            .context("Failed to parse negotiated handover Hs NDEF message")
    }

    fn parse_ndef_records(
        hs_message: ByteStr,
        ndef_records: &[NdefRecord],
        fallback_uuid: Option<Uuid>,
    ) -> Result<Self, anyhow::Error> {
        if ndef_records.len() < 3 {
            bail!("Not enough NDEF records");
        }
        debug!("NDEF records: {:?}", ndef_records);

        // Not all wallets emit records in the same order, so we locate each
        // record by its type rather than relying on a fixed index position.
        let device_engagement_record = ndef_records
            .iter()
            .find(|r| r.record_type() == b"iso.org:18013:deviceengagement")
            .ok_or_else(|| anyhow!("Missing device engagement NDEF record"))?;

        let cc_record = ndef_records
            .iter()
            .find(|r| r.record_type() == b"application/vnd.bluetooth.le.oob")
            .ok_or_else(|| anyhow!("Missing BLE OOB carrier capability NDEF record"))?;

        let device_engagement = cbor::from_slice(device_engagement_record.payload())
            .context("Could not parse device engagement CBOR bytes")?;

        let (holder_le_role, uuid, ble_device_address) =
            parse_cc_record(cc_record).context("failed to parse cc record")?;

        let uuid = match (uuid, fallback_uuid) {
            (Some(u), _) => u,
            (None, Some(fb)) => {
                debug!("Hs BLE OOB has no UUID; using Hr UUID as fallback");
                fb
            }
            (None, None) => bail!("Could not find UUID in NDEF record"),
        };

        Ok(Self {
            device_engagement,
            holder_le_role: holder_le_role.context("Could not find LE role in NDEF record")?,
            uuid,
            hs_message,
            hr_message: None,
            ble_device_address,
        })
    }
}

fn parse_cc_record(
    cc_record: &NdefRecord,
) -> Result<(Option<LeRole>, Option<Uuid>, Option<ByteStr>)> {
    let mut holder_le_role = None;
    let mut uuid = None;
    let mut ble_device_address = None;

    let mut remains = cc_record.payload();

    // Order of AD (Advertising and Scan Response Data) fields isn't mandated, so we have to take
    // out what we are interested in as we go.
    while !remains.is_empty() {
        let (info, remains_) = remains
            .split_first_chunk::<2>()
            .context("remainin cc record data did not have 2 bytes for the metadata")?;
        remains = remains_;
        // length includes the datatype byte
        let ad_len = info[0];
        let ad_datatype = info[1];
        let (ad_data, remains_) = remains
            .split_at_checked((ad_len - 1).into())
            .context("Remaining cc record data was not big enough for the length advertized")?;
        remains = remains_;
        match KnownType::try_from(ad_datatype) {
            Ok(KnownType::LeRole) => {
                if ad_len != 2 {
                    bail!("LE Role length expected to be 2, but got {ad_len}");
                }
                holder_le_role =
                    Some(LeRole::from_repr(ad_data[0]).context("Failed to parse LE role")?);
            }
            Ok(KnownType::CompleteList128BitServiceUuids) => match ad_len {
                17 => {
                    let mut uuid_bytes = ad_data.to_vec();
                    uuid_bytes.reverse();
                    uuid =
                        Some(Uuid::from_bytes(uuid_bytes.try_into().map_err(|_| {
                            anyhow!("UUID does not match advertised length")
                        })?));
                }
                l => bail!("Unsupported UUID length: {l}"),
            },
            Ok(KnownType::MacAddress) => match ad_len {
                // mac address is encoded in little endian
                7 => {
                    ble_device_address =
                        Some(ad_data.iter().copied().rev().collect::<Vec<u8>>().into());
                }
                8 => {
                    // Bluetooth® Secure Simple Pairing Using NFC specs have examples with 7 bytes
                    // long mac address (even though they say it should be 6 bytes long) and the
                    // last byte is seemingly discarded from the descriptions
                    ble_device_address = Some(
                        ad_data[..7]
                            .iter()
                            .copied()
                            .rev()
                            .collect::<Vec<u8>>()
                            .into(),
                    );
                }
                l => bail!("Unsupported MAC address length: {l}"),
            },
            _ => {
                info!("Unknown AD datatype: {:#2X?}", ad_datatype)
            }
        }
    }
    Ok((holder_le_role, uuid, ble_device_address))
}

#[cfg(test)]
mod test {
    use crate::definitions::device_engagement::nfc::{
        ndef_handover::get_static_handover_ndef_response, StaticHandoverState,
    };

    use super::*;

    #[test]
    fn roundtrip() {
        let state = StaticHandoverState::new().expect("failed to generate handover state");
        let handover_response =
            get_static_handover_ndef_response(state).expect("failed to get ndef message");
        ReaderNegotiatedCarrierInfo::parse_ndef_message(&handover_response.ndef)
            .expect("failed to parse ndef message");
    }

    #[test]
    fn generate_ts_ndef_format() {
        let ts = generate_ts_ndef(TNEP_HANDOVER_SERVICE_URI).expect("failed to generate Ts NDEF");
        // From multipaz test data: 0019 d1 02 14 54 73 13 <19 bytes of "urn:nfc:sn:handover">
        // Without the 2-byte length prefix used in APDUs, the NDEF itself is 25 bytes.
        let expected = hex::decode("d1021454731375726e3a6e66633a736e3a68616e646f766572").unwrap();
        assert_eq!(ts, expected);
    }

    #[test]
    fn parse_te_ndef_success() {
        // Well-Known "Te" single record: type_len=2, payload_len=1, type="Te", payload=[0x00]
        // D1=MB|ME|SR|TNF=WellKnown, 02=type_len, 01=payload_len, 5465="Te", 00=status
        let te_ndef = hex::decode("d102015465 00".replace(' ', "")).unwrap();
        parse_te_ndef(&te_ndef).expect("should accept Te with status 0x00");
    }

    #[test]
    fn parse_te_ndef_failure() {
        // Well-Known "Te" single record with non-zero status byte
        let te_ndef = hex::decode("d102015465 01".replace(' ', "")).unwrap();
        assert!(parse_te_ndef(&te_ndef).is_err());
    }

    #[test]
    fn detect_tp_service_finds_handover() {
        // Use the exact bytes from the multipaz_negotiated rapdu (excluding 0x9000):
        let tp_rapdu = &[
            0xD1u8, 0x02, 0x1A, 0x54, 0x70, 0x10, 0x13, 0x75, 0x72, 0x6E, 0x3A, 0x6E, 0x66, 0x63,
            0x3A, 0x73, 0x6E, 0x3A, 0x68, 0x61, 0x6E, 0x64, 0x6F, 0x76, 0x65, 0x72, 0x00, 0x00,
            0x0F, 0xFF, 0xFF,
        ];
        let service = detect_tp_service(tp_rapdu);
        assert_eq!(service.as_deref(), Some(TNEP_HANDOVER_SERVICE_URI));
    }

    #[test]
    fn generate_hr_ndef_is_valid() {
        let (hr_ndef, uuid) = generate_hr_ndef().expect("failed to generate Hr NDEF");
        assert!(!hr_ndef.is_empty());
        // The Hr NDEF should be parseable
        ndef_rs::NdefMessage::decode(hr_ndef).expect("Hr NDEF should be decodable by ndef_rs");
        // UUID should be a valid v4
        assert_eq!(uuid.get_version(), Some(uuid::Version::Random));
    }

    fn test_sample_cc_record(sample: Vec<u8>) {
        let ndef_message =
            ndef_rs::NdefMessage::decode(sample).expect("Failed to decode ndef message");
        let ndef_records = ndef_message.records();
        let cc_record = ndef_records
            .iter()
            .find(|r| r.record_type() == b"application/vnd.bluetooth.le.oob")
            .expect("couldn't find cc record");
        let (holder_le_role, _, ble_device_address) =
            parse_cc_record(cc_record).expect("failed to parse cc record");
        assert!(holder_le_role.is_some());
        assert!(ble_device_address.is_some());
        // those samples don't have Service Class UUID Bluetooth EIR Data Types
    }

    #[test]
    #[ignore = "doesn't have a BLE OOB record"]
    /// From Bluetooth® Secure Simple Pairing Using NFC
    /// Table 6: Binary Content of a Sample Bluetooth Handover Request Message
    fn sample_ble_handover_request_message_table_6() {
        let sample = vec![
            0x91, 0x02, 0x11, 0x48, 0x72, 0x13, 0x91, 0x02, 0x02, 0x63, 0x72, 0x01, 0x02, 0x51,
            0x02, 0x04, 0x61, 0x63, 0x01, 0x01, 0x30, 0x00, 0x5A, 0x20, 0x43, 0x01, 0x61, 0x70,
            0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E,
            0x62, 0x6C, 0x75, 0x65, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x2E, 0x65, 0x70, 0x2E, 0x6F,
            0x6F, 0x62, 0x30, 0x43, 0x00, 0x01, 0x07, 0x80, 0x80, 0xBF, 0xA1, 0x04, 0x0D, 0x20,
            0x06, 0x08, 0x11, 0x0E, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06,
            0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x11, 0x0F, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x05, 0x03, 0x06, 0x11,
            0x20, 0x11, 0x0B, 0x09, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65,
        ];
        test_sample_cc_record(sample);
    }

    #[test]
    #[ignore = "doesn't have a BLE OOB record"]
    /// From Bluetooth® Secure Simple Pairing Using NFC
    /// Table 7: Binary Content of a Sample Bluetooth Handover Select Message
    fn sample_ble_handover_request_message_table_7() {
        let sample = vec![
            0x91, 0x02, 0x0A, 0x48, 0x73, 0x13, 0xD1, 0x02, 0x04, 0x61, 0x63, 0x01, 0x01, 0x30,
            0x00, 0x5A, 0x20, 0x43, 0x01, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 0x62, 0x6C, 0x75, 0x65, 0x74, 0x6F, 0x6F,
            0x74, 0x68, 0x2E, 0x65, 0x70, 0x2E, 0x6F, 0x6F, 0x62, 0x30, 0x43, 0x00, 0x03, 0x07,
            0x80, 0x88, 0xbf, 0x01, 0x04, 0x0D, 0x80, 0x06, 0x04, 0x11, 0x0E, 0x0F, 0x0E, 0x0D,
            0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x11,
            0x0F, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
            0x02, 0x01, 0x00, 0x05, 0x03, 0x18, 0x11, 0x23, 0x11, 0x0B, 0x09, 0x44, 0x65, 0x76,
            0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65,
        ];
        test_sample_cc_record(sample);
    }

    #[test]
    /// From Bluetooth® Secure Simple Pairing Using NFC
    /// Table 8: Binary Content of a Bluetooth LE Handover Request Message
    fn sample_ble_handover_request_message_table_8() {
        let sample = vec![
            0x91, 0x02, 0x11, 0x48, 0x72, 0x13, 0x91, 0x02, 0x02, 0x63, 0x72, 0x01, 0x02, 0x51,
            0x02, 0x04, 0x61, 0x63, 0x01, 0x01, 0x30, 0x00, 0x5A, 0x20, 0x55, 0x01, 0x61, 0x70,
            0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E,
            0x62, 0x6C, 0x75, 0x65, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x2E, 0x6c, 0x65, 0x2E, 0x6F,
            0x6F, 0x62, 0x30, 0x08, 0x1B, 0x01, 0x07, 0x80, 0x80, 0xBF, 0xA1, 0x00, 0x02, 0x1C,
            0x03, 0x11, 0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
            0x11, 0x00, 0x00, 0x00, 0x11, 0x11, 0x22, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
            0x11, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x11, 0x23, 0x00, 0x00, 0x00,
            0x12, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x12, 0x03,
            0x19, 0x80, 0x00, 0x0B, 0x09, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d,
            0x65, 0x02, 0x01, 0x06,
        ];
        test_sample_cc_record(sample);
    }

    #[test]
    /// From Bluetooth® Secure Simple Pairing Using NFC
    /// Table 9: Binary Content of a Bluetooth LE Handover Select Message
    fn sample_ble_handover_request_message_table_9() {
        let sample = vec![
            0x91, 0x02, 0x0A, 0x48, 0x73, 0x13, 0xD1, 0x02, 0x04, 0x61, 0x63, 0x01, 0x01, 0x30,
            0x00, 0x5A, 0x20, 0x52, 0x01, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 0x62, 0x6C, 0x75, 0x65, 0x74, 0x6F, 0x6F,
            0x74, 0x68, 0x2E, 0x6c, 0x65, 0x2E, 0x6F, 0x6F, 0x62, 0x30, 0x08, 0x1B, 0xC8, 0xDC,
            0xF4, 0x55, 0x2A, 0x77, 0x01, 0x02, 0x1C, 0x00, 0x11, 0x10, 0x00, 0x00, 0x00, 0x11,
            0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x11, 0x22,
            0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00,
            0x00, 0x11, 0x11, 0x23, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00,
            0x00, 0x12, 0x00, 0x00, 0x00, 0x12, 0x03, 0x19, 0xC1, 0x03, 0x0B, 0x09, 0x44, 0x65,
            0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65,
        ];
        test_sample_cc_record(sample);
    }

    #[test]
    #[ignore = "doesn't have a BLE OOB record"]
    /// From Bluetooth® Secure Simple Pairing Using NFC
    /// Table 10: Binary Content of a Sample Bluetooth Handover Select Message on an NFC
    fn sample_ble_handover_request_message_table_10() {
        let sample = vec![
            0x91, 0x02, 0x0A, 0x48, 0x73, 0x13, 0xD1, 0x02, 0x04, 0x61, 0x63, 0x03, 0x01, 0x30,
            0x00, 0x5A, 0x20, 0x1F, 0x01, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 0x62, 0x6C, 0x75, 0x65, 0x74, 0x6F, 0x6F,
            0x74, 0x68, 0x2E, 0x65, 0x70, 0x2E, 0x6F, 0x6F, 0x62, 0x30, 0x1F, 0x00, 0x03, 0x07,
            0x80, 0x88, 0xbf, 0x01, 0x04, 0x0D, 0x80, 0x06, 0x04, 0x05, 0x03, 0x18, 0x11, 0x23,
            0x11, 0x0B, 0x09, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65,
        ];
        test_sample_cc_record(sample);
    }

    #[test]
    /// From Bluetooth® Secure Simple Pairing Using NFC
    /// Table 11: Binary Content of a Bluetooth LE Handover Select Message on an NFC Forum
    fn sample_ble_handover_request_message_table_11() {
        let sample = vec![
            0x91, 0x02, 0x0A, 0x48, 0x73, 0x13, 0xD1, 0x02, 0x04, 0x61, 0x63, 0x01, 0x01, 0x30,
            0x00, 0x5A, 0x20, 0x52, 0x01, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 0x62, 0x6C, 0x75, 0x65, 0x74, 0x6F, 0x6F,
            0x74, 0x68, 0x2E, 0x6c, 0x65, 0x2E, 0x6F, 0x6F, 0x62, 0x30, 0x08, 0x1B, 0x18, 0x3B,
            0x4B, 0x1C, 0x3B, 0xCA, 0x01, 0x02, 0x1C, 0x00, 0x11, 0x10, 0x00, 0x00, 0x00, 0x11,
            0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x11, 0x22,
            0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00,
            0x00, 0x11, 0x11, 0x23, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00,
            0x00, 0x12, 0x00, 0x00, 0x00, 0x12, 0x03, 0x19, 0xC1, 0x03, 0x0B, 0x09, 0x44, 0x65,
            0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65,
        ];
        test_sample_cc_record(sample);
    }
}
