#![no_main]

use isomdl::issuance::Mdoc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_cbor::from_slice::<Mdoc>(data);
});
