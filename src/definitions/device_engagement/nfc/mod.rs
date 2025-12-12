mod apdu;
#[allow(unused)]
mod ble;
mod ndef_handover;
mod ndef_handover_reader;
#[allow(unused)]
mod ndef_parser;
mod util;
use util::{impl_partial_enum, IntoRaw};

mod apdu_handover;
pub use apdu_handover::*;
mod apdu_handover_reader;
pub use apdu_handover_reader::*;

pub use ndef_handover::BleInfo as NegotiatedBleInfo;
pub use ndef_handover::NegotiatedCarrierInfo;
pub use ndef_handover_reader::ReaderNegotiatedCarrierInfo;

// TODO don't use Reader prefix, just rely on paths
