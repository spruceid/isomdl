use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    cbor,
    definitions::{
        device_engagement::nfc::{ble::ad_packet::KnownType, ndef_handover::LeRole},
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
    pub uuid: uuid::Uuid, // TODO currently unused
    pub holder_le_role: LeRole, // TODO currently unused
}

impl ReaderNegotiatedCarrierInfo {
    pub fn parse_ndef_message(
        ndef_response: &[u8],
        negotiated: bool,
    ) -> Result<Self, anyhow::Error> {
        if negotiated {
            unimplemented!("Negotiated handover not yet implemented");
        }
        let ndef_message =
            ndef_rs::NdefMessage::decode(ndef_response).context("Failed to decode ndef message")?;
        let ndef_records = ndef_message.records();
        if ndef_records.len() < 3 {
            bail!("Not enough NDEF records");
        }
        // let hs_record = &ndef_records[0];
        let device_engagement_record = &ndef_records[1];
        let cc_record = &ndef_records[2];

        let (uuid, holder_le_role) = {
            if cc_record.record_type() != b"application/vnd.bluetooth.le.oob" {
                bail!("cc record does not have correct type");
            }
            let (info, uuid) = cc_record
                .payload()
                .split_first_chunk::<5>()
                .context("uuid payload did not have at least 5 bytes")?;
            let le_role_len = info[0];
            let le_role_datatype = info[1];
            let le_role = info[2];
            let uuid_len = info[3];
            let unknown = info[4];

            if le_role_len != 2 {
                bail!("LE Role length expected to be 2, but got {le_role_len}");
            }
            if le_role_datatype != KnownType::LeRole as u8 {
                bail!("Type doesn't match LeRole");
            }
            if unknown != KnownType::CompleteList128BitServiceUuids as u8 {
                bail!("Type doesn't match CompleteList128BitServiceUuids ");
            }
            let holder_le_role = LeRole::from_repr(le_role).context("Failed to parse LE role")?;
            let uuid = match uuid_len {
                // TODO why does the holder have 17 instead of 16?
                17 => Uuid::from_bytes(
                    uuid.try_into()
                        .context("UUID does not match advertised length")?,
                ),
                l => bail!("Unsupported UUID length: {l}"),
            };
            (uuid, holder_le_role)
        };

        let device_engagement = {
            if device_engagement_record.record_type() != b"iso.org:18013:deviceengagement" {
                bail!("device engagement record does not have correcty type");
            }
            cbor::from_slice(device_engagement_record.payload())
                .context("Could not parse device engagement CBOR bytes")?
        };

        Ok(Self {
            uuid,
            device_engagement,
            holder_le_role,
        })
    }
}
