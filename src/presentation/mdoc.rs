use crate::definitions::{
    device_engagement::{DeviceRetrievalMethod, RetrievalOptions, Security},
    helpers::{ByteStr, Tag24},
    session::{decrypt, derive_session_key, get_shared_secret, Curves},
    CoseKey, DeviceEngagement, SessionEstablishment,
};
use anyhow::{Error, Ok, Result};
use p256::{ecdh::EphemeralSecret, NistP256};

fn prepare_device_engagement(
    retrieval_option: RetrievalOptions,
    public_key: CoseKey,
) -> Result<Tag24<DeviceEngagement>> {
    let type_and_version = get_transport_type_and_version(retrieval_option.clone())?;
    let e_device_key_bytes = Tag24::<CoseKey>::new(public_key)?;

    let device_retrieval_option = DeviceRetrievalMethod {
        transport_type: type_and_version.0,
        version: type_and_version.1,
        retrieval_method: retrieval_option,
    };
    let device_retrieval_options = vec![device_retrieval_option];

    let security: Security = Security {
        cipher_suite_identifier: 1,
        e_device_key_bytes: e_device_key_bytes,
    };

    let device_engagement = DeviceEngagement {
        //version 1.0 is the only version to date
        version: "1.0".to_string(),
        security: security,
        device_retrieval_methods: Some(device_retrieval_options),
        //server_retrieval is not implemented
        server_retrieval_methods: None,
        //protocol_info is not implemented
        protocol_info: None,
    };

    let device_engagement_bytes = Tag24::<DeviceEngagement>::new(device_engagement)?;

    Ok(device_engagement_bytes)
}

fn get_cypher_suite_identifier(crv: Curves) -> u64 {
    match crv {
        Curves::P256 => 1,
        Curves::P384 => 2,
        Curves::P521 => 3,
        Curves::X25519 => 4,
        Curves::X448 => 5,
        Curves::Ed25519 => 6,
        Curves::Ed448 => 7,
    }
}

fn get_transport_type_and_version(retrieval_option: RetrievalOptions) -> Result<(u64, u64)> {
    match retrieval_option {
        RetrievalOptions::NFCOPTIONS(_) => Ok((1, 1)),
        RetrievalOptions::BLEOPTIONS(_) => Ok((2, 1)),
        RetrievalOptions::WIFIOPTIONS(_) => Ok((3, 1)),
    }
}

pub fn process_session_establishment(
    session_establishment_bytes: Tag24<SessionEstablishment>,
    e_device_key_priv: EphemeralSecret,
    message_count: [u8; 4],
) -> Result<ByteStr> {
    // derive session keys
    let session_establishment = session_establishment_bytes.into_inner();
    let reader_key_bytes = session_establishment.e_reader_key;
    let shared_secret = get_shared_secret(reader_key_bytes.into_inner(), e_device_key_priv)?;
    let sk_reader = derive_session_key(&shared_secret, true)?;
    let _sk_device = derive_session_key(&shared_secret, false)?;

    //decrypt mdoc request
    let data = decrypt(
        sk_reader,
        Vec::<u8>::from(session_establishment.data),
        message_count,
        false,
    )
    .map_err(|_e| Error::msg("decryption failed"))?;

    //parse mdoc request

    //prepare mdoc response

    //encrypt mdoc responce and prepare session_data
    Ok(data)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::definitions::{
        device_engagement::RetrievalOptions,
        helpers::{ByteStr, Tag24},
        session::create_p256_ephemeral_keys,
        BleOptions, DeviceEngagement,
    };
    use serde_cbor::Error as SerdeCborError;

    #[test]
    fn device_engagement_cbor_roundtrip() {
        let key_pair = create_p256_ephemeral_keys();
        let public_key = key_pair.unwrap().1;

        let uuid_bytes: Vec<u8> = vec![1, 2, 3, 4, 5];
        let address_bytes: Vec<u8> = vec![6, 7, 8, 9, 0];

        let ble_option = BleOptions {
            peripheral_server_mode: false,
            central_client_mode: true,
            peripheral_server_uuid: None,
            client_central_uuid: Some(ByteStr::from(uuid_bytes)),
            mdoc_ble_device_address_peripheral_server: Some(ByteStr::from(address_bytes)),
        };

        let device_engagement_bytes =
            prepare_device_engagement(RetrievalOptions::BLEOPTIONS(ble_option), public_key)
                .expect("failed to prepare for device engagement");

        let device_engagement: Result<DeviceEngagement, SerdeCborError> =
            serde_cbor::from_slice(device_engagement_bytes.inner_bytes.as_ref());

        let _tagged_device_engagement = Tag24::<DeviceEngagement>::new(device_engagement.unwrap());
    }
}
