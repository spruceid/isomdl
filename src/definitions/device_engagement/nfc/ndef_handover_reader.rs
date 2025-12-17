use anyhow::{anyhow, bail, Context};
use ndef_rs::{NdefRecord, TNF};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    cbor,
    definitions::{
        device_engagement::nfc::{
            ble::ad_packet::KnownType,
            ndef_handover::{LeRole, RecordType},
        },
        helpers::ByteStr,
        DeviceEngagement,
    },
};

#[derive(Debug, Clone)]
pub enum ReaderHandoverState {
    WaitingForAidResponse,
    WaitingForCapabilitiesFileResponse,
    WaitingForCapabilitiesReadResponse,
    WaitingForNdefFileResponse,
    WaitingForNdefReadResponse,
    Done,
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
            None => Self::parse_ndef_message_static(hs_message, ndef_records)
                .context("Failed to parse static handover NDEF message"),
            Some(_) => bail!("negotiated handover not supported"),
        }
    }

    fn parse_ndef_message_static(
        hs_message: ByteStr,
        ndef_records: &[NdefRecord],
    ) -> Result<Self, anyhow::Error> {
        if ndef_records.len() < 3 {
            bail!("Not enough NDEF records");
        }
        // let hs_record = &ndef_records[0];
        let device_engagement_record = &ndef_records[1];
        let cc_record = &ndef_records[2];

        let device_engagement: DeviceEngagement = {
            if device_engagement_record.record_type() != b"iso.org:18013:deviceengagement" {
                bail!("device engagement record does not have correcty type");
            }
            cbor::from_slice(device_engagement_record.payload())
                .context("Could not parse device engagement CBOR bytes")?
        };

        let (uuid, holder_le_role) = {
            if cc_record.record_type() != b"application/vnd.bluetooth.le.oob" {
                bail!("cc record does not have correct type");
            }
            let (info, uuid_bytes) = cc_record
                .payload()
                .split_first_chunk::<5>()
                .context("uuid payload did not have at least 5 bytes")?;
            let le_role_len = info[0];
            let le_role_datatype = info[1];
            let le_role = info[2];
            let uuid_len = info[3];
            let eir_datatype = info[4]; // Extended Inquiry Response (?)

            if le_role_len != 2 {
                bail!("LE Role length expected to be 2, but got {le_role_len}");
            }
            if le_role_datatype != KnownType::LeRole as u8 {
                bail!("Type doesn't match LeRole");
            }
            if eir_datatype != KnownType::CompleteList128BitServiceUuids as u8 {
                bail!("Type doesn't match CompleteList128BitServiceUuids ");
            }
            let holder_le_role = LeRole::from_repr(le_role).context("Failed to parse LE role")?;
            let uuid = match uuid_len {
                // this is length of UUID + 1 because it includes the data type byte
                17 => {
                    let mut uuid_bytes = uuid_bytes.to_vec();
                    uuid_bytes.reverse();
                    Uuid::from_bytes(
                        uuid_bytes
                            .try_into()
                            .map_err(|_| anyhow!("UUID does not match advertised length"))?,
                    )
                }
                l => bail!("Unsupported UUID length: {l}"),
            };
            (uuid, holder_le_role)
        };

        Ok(Self {
            device_engagement,
            holder_le_role,
            uuid,
            hs_message,
            hr_message: None,
        })
    }
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
}
