// The NDEF crate has a broken parser. It parses TNF fields as 4 bits, rather than 3.
// TODO: Should we trust its message creation if its message reader is fundamentally broken?

use thiserror::Error;

use crate::definitions::device_engagement::nfc::{ndef::RawPayload, util::DisplayBytesAsHex};

#[derive(Debug, Error)]
pub enum ReadRecordError {
    #[error("Buffer too small: cursor={cursor}, buffer_len={buffer_len}, required_space={required_space}, rem={rem}", rem = buffer_len - cursor)]
    BufferTooSmall {
        cursor: usize,
        required_space: usize,
        buffer_len: usize,
    },
    #[error("Unknown or invalid TNF: {0:x}")]
    UnknownOrInvalidTnf(u8),
}

#[derive(Debug, Clone, Copy, strum_macros::FromRepr, PartialEq)]
#[repr(u8)]
// NDEF §3.2.6
pub enum TNF {
    Empty = 0x00,
    WellKnown = 0x01,
    Media = 0x02,
    AbsoluteUri = 0x03,
    External = 0x04,
    Unknown = 0x05,
    Unchanged = 0x06,
}

impl TNF {
    pub fn to_ndef_rs(self) -> ndef_rs::TNF {
        ndef_rs::TNF::from_repr(self as u8).unwrap_or(ndef_rs::TNF::Unknown) // This cannot fail.
    }
}

// NDEF §3.2
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RawNdefRecord<'a> {
    pub mb: bool,
    pub me: bool,
    pub cf: bool,
    pub sr: bool,
    pub il: bool,
    pub tnf: u8,
    pub type_bytes: &'a [u8],
    pub id: Option<&'a [u8]>,
    pub payload: &'a [u8],
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct NdefRecord<'a> {
    pub first_record: bool,
    pub last_record: bool,
    pub first_or_middle_chunk: bool,
    pub tnf: TNF,
    pub type_bytes: &'a [u8],
    pub id: Option<&'a [u8]>,
    pub payload: &'a [u8],
}

impl<'a> std::fmt::Debug for NdefRecord<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ret = f.debug_struct("NdefRecord");
        ret.field("first_record", &self.first_record)
            .field("last_record", &self.last_record)
            .field("first_or_middle_chunk", &self.first_or_middle_chunk)
            .field("tnf", &self.tnf);
        match str::from_utf8(&self.type_bytes) {
            Ok(type_str) => ret.field("type_bytes", &type_str),
            Err(_) => ret.field("type_bytes", &self.type_bytes),
        };
        match self.id.map(|id| str::from_utf8(id)) {
            Some(Ok(id_str)) => ret.field("id", &Some(id_str)),
            _ => ret.field("id", &self.id),
        };
        ret.field("payload", &DisplayBytesAsHex::from(self.payload))
            .finish()
    }
}

impl<'a> TryFrom<RawNdefRecord<'a>> for NdefRecord<'a> {
    type Error = ReadRecordError;

    fn try_from(raw_record: RawNdefRecord<'a>) -> Result<Self, Self::Error> {
        let Some(tnf) = TNF::from_repr(raw_record.tnf) else {
            return Err(ReadRecordError::UnknownOrInvalidTnf(raw_record.tnf));
        };
        Ok(Self {
            first_record: raw_record.mb,
            last_record: raw_record.me,
            first_or_middle_chunk: raw_record.cf,
            tnf,
            type_bytes: raw_record.type_bytes,
            id: raw_record.id,
            payload: raw_record.payload,
        })
    }
}

impl<'a> NdefRecord<'a> {
    pub fn iterator_from_bytes(
        bytes: &[u8],
    ) -> impl Iterator<Item = Result<NdefRecord, ReadRecordError>> {
        let mut failed = false;
        RawNdefRecord::iterator_from_bytes(bytes).flat_map(move |raw| {
            if failed {
                return None;
            }
            let raw = match raw {
                Ok(raw) => raw,
                Err(err) => return Some(Err(err)),
            };
            match NdefRecord::try_from(raw) {
                Ok(record) => Some(Ok(record)),
                Err(err) => {
                    failed = true;
                    Some(Err(err))
                }
            }
        })
    }
    pub fn to_ndef_rs(&self) -> ndef_rs::Result<ndef_rs::NdefRecord> {
        let mut builder = ndef_rs::NdefRecord::builder();
        if let Some(id) = self.id {
            builder = builder.id(id.into());
        }
        builder
            .tnf(self.tnf.to_ndef_rs())
            .payload(&RawPayload {
                record_type: self.type_bytes,
                payload: self.payload,
            })
            .build()
    }
}

impl<'a> RawNdefRecord<'a> {
    pub fn iterator_from_bytes(
        bytes: &[u8],
    ) -> impl Iterator<Item = Result<RawNdefRecord, ReadRecordError>> {
        let mut cursor = 0;
        let mut failed = false;
        std::iter::from_fn(move || {
            if failed {
                return None;
            }
            // NDEF §3.2
            if bytes.len() < cursor + 10 {
                if bytes.len() != cursor {
                    failed = true;
                    return Some(Err(ReadRecordError::BufferTooSmall {
                        cursor: cursor,
                        required_space: 10,
                        buffer_len: bytes.len(),
                    }));
                }
                return None;
            }
            let flags_byte = bytes[cursor];
            // 7  6  5  4  3  2  1  0
            // MB ME CF SR IL TNF----
            let mb = flags_byte & 0b10000000 != 0; // Start of NDEF message
            let me = flags_byte & 0b01000000 != 0; // End of NDEF message
            let cf = flags_byte & 0b00100000 != 0; // First or middle record chunk
            let sr = flags_byte & 0b00010000 != 0; // Short record
            let il = flags_byte & 0b00001000 != 0; // has ID field?
            let tnf = flags_byte & 0b00000111; // NDEF 3.2.6
            cursor += 1;

            let type_len = bytes[cursor] as usize;
            cursor += 1;

            // NDEF §3.2.4
            let payload_len = if sr {
                let payload_len = bytes[cursor] as usize;
                cursor += 1;
                payload_len
            } else {
                let payload_len_by = [
                    bytes[cursor + 0],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ];
                cursor += 4;
                u32::from_be_bytes(payload_len_by) as usize
            };
            let id_len = if il {
                let id_len = bytes[cursor] as usize;
                cursor += 1;
                id_len
            } else {
                0
            };
            if cursor + type_len > bytes.len() {
                failed = true;
                return Some(Err(ReadRecordError::BufferTooSmall {
                    cursor: cursor,
                    required_space: type_len,
                    buffer_len: bytes.len(),
                }));
            }
            let ty = &bytes[cursor..cursor + type_len];
            cursor += type_len;
            if cursor + id_len > bytes.len() {
                failed = true;
                return Some(Err(ReadRecordError::BufferTooSmall {
                    cursor: cursor,
                    required_space: id_len,
                    buffer_len: bytes.len(),
                }));
            }
            let id = if il {
                let id = &bytes[cursor..cursor + id_len];
                cursor += id_len;
                Some(id)
            } else {
                None
            };
            if cursor + payload_len > bytes.len() {
                failed = true;
                return Some(Err(ReadRecordError::BufferTooSmall {
                    cursor: cursor,
                    required_space: payload_len,
                    buffer_len: bytes.len(),
                }));
            }
            let payload = &bytes[cursor..cursor + payload_len];
            cursor += payload_len;

            Some(Ok(RawNdefRecord {
                mb,
                me,
                cf,
                sr,
                il,
                tnf,
                type_bytes: ty,
                id,
                payload,
            }))
        })
    }
}
