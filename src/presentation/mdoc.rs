use crate::definitions::{
    device_engagement::{DeviceRetrievalMethod, Security, ServerRetrievalMethods},
    helpers::{tag24, ByteStr, NonEmptyVec, Tag24},
    session::{self, derive_session_key, get_shared_secret, Handover, SessionTranscript},
    CoseKey, DeviceEngagement, SessionEstablishment,
};
use aes_gcm::Aes256Gcm;
use p256::ecdh::EphemeralSecret;

pub struct SessionManagerInit {
    e_device_key_private: EphemeralSecret,
    device_engagement: Tag24<DeviceEngagement>,
}

pub struct SessionManagerEngaged {
    e_device_key_private: EphemeralSecret,
    device_engagement: Tag24<DeviceEngagement>,
    handover: Handover,
}

// TODO: remove this once implementation is complete.
#[allow(dead_code)]
pub struct SessionManager {
    e_device_key_private: EphemeralSecret,
    session_transcript: Tag24<SessionTranscript>,
    sk_device: Aes256Gcm,
    device_message_counter: u32,
    sk_reader: Aes256Gcm,
    reader_message_counter: u32,
    state: State,
}

#[derive(Clone, Debug)]
pub enum State {
    AwaitingRequest,
    AwaitingSigning(PreparedDeviceResponse),
    ReadyToRespond(ByteStr),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to generate ephemeral key: {0}")]
    EKeyGeneration(session::Error),
    #[error("error converting value to CBOR: {0}")]
    CborConversion(tag24::Error),
    #[error("unable to generate shared secret: {0}")]
    SharedSecretGeneration(anyhow::Error),
}

impl SessionManagerInit {
    /// Initialise the SessionManager.
    pub fn initialise(
        device_retrieval_methods: Option<NonEmptyVec<DeviceRetrievalMethod>>,
        server_retrieval_methods: Option<ServerRetrievalMethods>,
    ) -> Result<Self, Error> {
        let (e_device_key_private, e_device_key_pub) =
            session::create_p256_ephemeral_keys().map_err(Error::EKeyGeneration)?;
        let e_device_key_bytes =
            Tag24::<CoseKey>::new(e_device_key_pub).map_err(Error::CborConversion)?;
        let security = Security(1, e_device_key_bytes);

        let device_engagement = DeviceEngagement {
            version: "1.0".to_string(),
            security,
            device_retrieval_methods,
            server_retrieval_methods,
            protocol_info: None,
        };

        let device_engagement =
            Tag24::<DeviceEngagement>::new(device_engagement).map_err(Error::CborConversion)?;

        Ok(Self {
            e_device_key_private,
            device_engagement,
        })
    }

    /// Begin device engagement using QR code.
    pub fn qr_engagement(self) -> (SessionManagerEngaged, String) {
        let mut qr_code_uri = String::from("mdoc:");
        let config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        base64::encode_config_buf(
            &self.device_engagement.inner_bytes,
            config,
            &mut qr_code_uri,
        );
        let sm = SessionManagerEngaged {
            device_engagement: self.device_engagement,
            e_device_key_private: self.e_device_key_private,
            handover: Handover::QR,
        };
        (sm, qr_code_uri)
    }
}

impl SessionManagerEngaged {
    pub fn process_session_establishment(
        self,
        session_establishment: SessionEstablishment,
    ) -> Result<SessionManager, Error> {
        let e_reader_key = session_establishment.e_reader_key;
        let session_transcript = Tag24::new(SessionTranscript(
            self.device_engagement,
            e_reader_key.clone(),
            self.handover,
        ))
        .map_err(Error::CborConversion)?;

        let shared_secret =
            get_shared_secret(e_reader_key.into_inner(), &self.e_device_key_private)
                .map_err(Error::SharedSecretGeneration)?;

        let sk_reader = derive_session_key(&shared_secret, &session_transcript, true);

        let sk_device = derive_session_key(&shared_secret, &session_transcript, false);

        let mut sm = SessionManager {
            e_device_key_private: self.e_device_key_private,
            session_transcript,
            sk_device,
            device_message_counter: 0,
            sk_reader,
            reader_message_counter: 0,
            state: State::AwaitingRequest,
        };

        sm.handle_request(session_establishment.data);

        Ok(sm)
    }
}

impl SessionManager {
    pub fn handle_request(&mut self, _request: ByteStr) {
        // Check state is `AwaitingRequest`.
        // Decrypt request.
        // Prepare response.
        self.state = State::AwaitingSigning(PreparedDeviceResponse {})
    }
}

#[derive(Clone, Debug)]
pub struct PreparedDeviceResponse {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::definitions::{
        device_engagement::{CentralClientMode, DeviceRetrievalMethod},
        helpers::Tag24,
        session::create_p256_ephemeral_keys,
        BleOptions, DeviceEngagement,
    };

    #[test]
    fn device_engagement_cbor_roundtrip() {
        let key_pair = create_p256_ephemeral_keys().unwrap();
        let public_key = Tag24::new(key_pair.1).unwrap();

        let uuid = uuid::Uuid::now_v1(&[0, 1, 2, 3, 4, 5]);

        let ble_option = BleOptions {
            peripheral_server_mode: None,
            central_client_mode: Some(CentralClientMode { uuid }),
        };

        let device_retrieval_methods =
            Some(NonEmptyVec::new(DeviceRetrievalMethod::BLE(ble_option)));

        let device_engagement = DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, public_key),
            device_retrieval_methods,
            server_retrieval_methods: None,
            protocol_info: None,
        };

        let bytes = serde_cbor::to_vec(&device_engagement).unwrap();
        let roundtripped = serde_cbor::from_slice(&bytes).unwrap();

        assert_eq!(device_engagement, roundtripped)
    }
}
