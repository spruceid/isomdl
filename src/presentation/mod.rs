pub mod device;
pub mod reader;

use anyhow::Result;
use base64::{decode, encode};
use serde::{Deserialize, Serialize};

pub trait Stringify: Serialize + for<'a> Deserialize<'a> {
    fn stringify(&self) -> Result<String> {
        let data = serde_cbor::to_vec(self)?;
        let encoded = encode(data);
        Ok(encoded)
    }

    fn parse(encoded: String) -> Result<Self> {
        let data = decode(encoded)?;
        let this = serde_cbor::from_slice(&data)?;
        Ok(this)
    }
}

impl Stringify for device::Document {}
impl Stringify for device::SessionManagerInit {}
impl Stringify for device::SessionManagerEngaged {}
impl Stringify for device::SessionManager {}
impl Stringify for reader::SessionManager {}

#[test]
fn debug() {
    let b64 = "pGlkb2N1bWVudHOhdW9yZy5pc28uMTgwMTMuNS4xLm1ETKRiaWRQVuYCQFVAEe2ZpQAAAAAAAGtpc3N1ZXJfYXV0aIRDoQEmoRghgVkBkzCCAY8wggE1oAMCAQICFDo00EDi78wK74UqwxVT3diWP/LaMAoGCCqGSM49BAMCMB0xGzAZBgNVBAoMElNwcnVjZSBTeXN0ZW1zIEx0ZDAeFw0yMjA5MTIxNDE4NTJaFw0yMjEwMTIxNDE4NTJaMB0xGzAZBgNVBAoMElNwcnVjZSBTeXN0ZW1zIEx0ZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNrnSBTUABeZM5zd2PBnfb8pxa27ei0fVfZhcazlrvmT3ju86pH/OaiHJYGkNyy74wi2zYs8tGJhp5N5gcA2hkSjUzBRMB0GA1UdDgQWBBRYUED6a1+qE0JpltF88QAYMqeAhjAfBgNVHSMEGDAWgBRYUED6a1+qE0JpltF88QAYMqeAhjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDo8ND0wpV40zH8eh2mivflxVNVJH0+crY2IP5Q0R+bAAIgAxqkCJc4i/zsyURWcflfwvk/w175dsuIsxvJh6FrcdNZAzjYGFkDM6ZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMaobZB1zuPW91GlYIO0heabszDKCLukuig0OtDAwODcjTkK25rKHzMAtxdw7G10sTqLVtADAWCA9DFS4mivKt0SmCatgYSgVC0Pc3iMWmcpZKOlZ0m0zOBuj4nNRMDc0X1ggkTWX6He5O7/mc1Fz2pgjFDYFz8bnD1dShjHnJbyGMHkbqFYPARWWG6NYIDIaZmDhgM8yhGMDB67Y4pV/KyRsaFYuhs6EGoPDRUMyG8WcZKu1AGNJWCCR1gSzUv+ijoAEHNymSwzuBYQyv0+xiWx";
    let conf =
        base64::Config::new(base64::CharacterSet::Standard, false).decode_allow_trailing_bits(true);
    let bytes = base64::decode_config(b64, conf).unwrap();
    let hex = hex::encode(bytes);
    println!("hex: {}", hex);
}
