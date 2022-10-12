use crate::definitions::{
    device_engagement::{self, BleOptions, DeviceRetrievalMethod, RetrievalOptions, Security},
    helpers::{ByteStr, Tag24},
    session::{create_p256_ephemeral_keys, Curves, EncodedPoints},
    CoseKey, DeviceEngagement, SessionData, SessionEstablishment,
};
use anyhow::Result;
use serde_cbor::Error as SerdeCborError;
use serde_cbor::Value as CborValue;

fn prepare_device_engagement(
    crv: Curves,
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn device_engagement_cbor_roundtrip() {
        let crv = Curves::P256;
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
            prepare_device_engagement(crv, RetrievalOptions::BLEOPTIONS(ble_option), public_key)
                .expect("failed to prepare for device engagement");

        let device_engagement: Result<DeviceEngagement, SerdeCborError> =
            serde_cbor::from_slice(device_engagement_bytes.inner_bytes.as_ref());

        let tagged_device_engagement = Tag24::<DeviceEngagement>::new(device_engagement.unwrap());
    }
}
