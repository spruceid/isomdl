use crate::definitions::session::get_shared_secret;
use crate::definitions::DeviceEngagement;
use crate::definitions::{
    device_engagement,
    session::{create_p256_ephemeral_keys, DeviceEngagementBytes, SharedSecrets},
    SessionEstablishment,
};
use anyhow::{Error, Result};
use hex_literal::hex;
use hkdf::Hkdf;
use serde_cbor::Value as CborValue;
use sha2::Sha256;

pub fn establish_session(
    device_engagement_bytes: DeviceEngagementBytes,
) -> Result<SessionEstablishment> {
    //generate own keys
    let key_pair = create_p256_ephemeral_keys()?;
    let private_key = key_pair.0;
    let public_key = key_pair.1;

    //decode device_engagement
    let device_engagement = DeviceEngagement::try_from(CborValue::from(device_engagement_bytes))?;

    // derive shared secret

    //let shared_secret = get_shared_secret(cose_key, encoded_point, e_device_key_priv);
    todo!()
}

fn derive_session_keys(shared_secret: SharedSecrets) {}

fn prepare_session_establishment() {}
