use crate::mdoc::bytestr::ByteStr;
use crate::mdoc::CoseKey;
use serde_cbor::Value as CborValue;

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;

pub struct SessionEstablishment {
    e_reader_key: EReaderKey,
    data: ByteStr,
}

pub struct SessionData {
    data: ByteStr,
    status: u64,
}
