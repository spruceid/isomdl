use crate::definitions::device_engagement::nfc::util::KnownOrRaw;

pub mod ad_packet {
    use thiserror::Error;

    use crate::definitions::device_engagement::nfc::{impl_partial_enum, IntoRaw};

    #[derive(Debug, Clone, Error)]
    #[error("Unknown AD packet type: {0}")]
    pub struct UnknownAdPacketType(pub u8);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, strum_macros::EnumIter)]
    #[repr(u8)]
    pub enum KnownType {
        LeRole = 0x1c,
        CompleteList128BitServiceUuids = 0x07,
        MacAddress = 0x1b,
        PeripheralServerMode = 0x77,
    }

    impl_partial_enum!(KnownType, u8);
}

pub struct AdPacket<'a> {
    pub kind: KnownOrRaw<u8, ad_packet::KnownType>,
    pub data: &'a [u8],
}

impl<'a> AdPacket<'a> {
    pub fn parse_buffer(buffer: &'a [u8]) -> impl Iterator<Item = Self> {
        let mut cursor = 0;
        std::iter::from_fn(move || {
            if cursor >= buffer.len() {
                return None;
            }
            let len = buffer[cursor] as usize;
            cursor += 1;
            if cursor + len > buffer.len() {
                return None;
            }
            let ad_type = buffer[cursor];
            let ad_data = &buffer[cursor + 1..cursor + len];
            cursor += len;

            Some(Self {
                kind: ad_type.into(),
                data: ad_data,
            })
        })
    }
}
