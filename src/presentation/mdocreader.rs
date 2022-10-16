//use crate::definitions::DeviceEngagement;
//use crate::definitions::{
//    session::{
//        create_p256_ephemeral_keys, derive_session_key, get_shared_secret, DeviceEngagementBytes,
//    },
//    SessionEstablishment,
//};
//use anyhow::Result;
//use serde_cbor::Value as CborValue;
//
//pub fn establish_session(
//    device_engagement_bytes: DeviceEngagementBytes,
//) -> Result<SessionEstablishment> {
//    //generate own keys
//    let key_pair = create_p256_ephemeral_keys()?;
//    let reader_private_key = key_pair.0;
//    let _reader_public_key = key_pair.1;
//
//    //decode device_engagement
//    let device_engagement =
//        DeviceEngagement::try_from(CborValue::from(device_engagement_bytes.clone()))?;
//    let mdoc_public_key = device_engagement.security.e_device_key_bytes;
//
//    // derive shared secret
//    let shared_secret =
//        get_shared_secret(mdoc_public_key.clone().into_inner(), reader_private_key)?;
//
//    //derive session keys
//    let _sk_reader = derive_session_key(
//        &shared_secret,
//        _reader_public_key,
//        device_engagement_bytes.clone(),
//        true,
//    )?;
//    let _sk_device = derive_session_key(
//        &shared_secret,
//        mdoc_public_key.into_inner(),
//        device_engagement_bytes,
//        false,
//    )?;
//
//    //prepare mdoc request for session establishment
//    //encrypt mdoc request + add unencrypted reader_public_key
//    todo!()
//}
