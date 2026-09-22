#![allow(dead_code)]
use anyhow::{anyhow, Context, Result};
use digest::Mac;
use hmac::Hmac;
use isomdl::cbor;
use isomdl::definitions::device_engagement::{CentralClientMode, DeviceRetrievalMethods};
use isomdl::definitions::device_request::{DataElements, DocType, ItemsRequest, Namespaces};
use isomdl::definitions::device_signed::DeviceAuthType;
use isomdl::definitions::helpers::{NonEmptyMap, NonEmptyVec};
use isomdl::definitions::session::Handover;
use isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry;
use isomdl::definitions::x509::validation::{AnyDocType, MdocProfile};
use isomdl::definitions::{self, BleOptions, DeviceRetrievalMethod};
use isomdl::presentation::device::{Document, Documents, RequestedItems, SessionManagerEngaged};
use isomdl::presentation::{
    authentication::{DocumentError, RequestAuthenticationOutcome},
    device, reader, Stringify,
};
use sha2::Sha256;
use signature::Signer;
use uuid::Uuid;

pub use isomdl::definitions::MDL_DOC_TYPE as DOC_TYPE;
pub const NAMESPACE: &str = "org.iso.18013.5.1";
pub const AGE_OVER_21_ELEMENT: &str = "age_over_21";

pub struct Device {}

impl Device {
    /// Parse the mDL encoded string into a [Documents] object.
    pub fn parse_mdl() -> Result<NonEmptyMap<DocType, Document>> {
        let mdl_encoded = include_str!("data/stringified-mdl.txt");
        let mdl = Document::parse(mdl_encoded.to_string()).context("could not parse mDL")?;
        let docs = Documents::new(DOC_TYPE.to_string(), mdl);
        Ok(docs)
    }

    /// Creates a QR code containing `DeviceEngagement` data, which includes its public key.
    pub fn initialise_session() -> Result<SessionManagerEngaged> {
        // Parse the mDL
        let docs = Device::parse_mdl()?;

        let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
            peripheral_server_mode: None,
            central_client_mode: Some(CentralClientMode {
                uuid: Uuid::new_v4(),
            }),
        }));

        let session = device::SessionManagerInit::initialise(docs, Some(drms), None)
            .context("failed to initialize device")?;

        session
            .engage(Handover::QR)
            .context("could not generate qr engagement")
    }

    /// Establishes the reader session from the given QR code and create request for needed elements.
    pub fn establish_reader_session(qr: String) -> Result<(reader::SessionManager, Vec<u8>)> {
        let requested_elements = Namespaces::new(
            NAMESPACE.into(),
            DataElements::new(AGE_OVER_21_ELEMENT.to_string(), false),
        );

        let trust_anchors = TrustAnchorRegistry::default();

        let (reader_sm, session_request, _ble_ident) = reader::SessionManager::establish_session(
            reader::Handover::QR(qr),
            NonEmptyVec::new(ItemsRequest::mdl(requested_elements)),
            trust_anchors,
        )
        .context("failed to establish reader session")?;
        Ok((reader_sm, session_request))
    }

    /// The Device handles the request from the reader and advances the state.
    pub async fn handle_request(
        state: SessionManagerEngaged,
        request: Vec<u8>,
        trusted_verifiers: TrustAnchorRegistry,
    ) -> Result<(device::SessionManager, RequestAuthenticationOutcome)> {
        let (session_manager, validated_request) = {
            let session_establishment: definitions::SessionEstablishment =
                cbor::from_slice(&request).context("could not deserialize request")?;
            // Use () to skip CRL checks in tests
            state
                .process_session_establishment(
                    session_establishment,
                    trusted_verifiers,
                    &AnyDocType(MdocProfile::MDL),
                    &(),
                )
                .await
                .context("could not process process session establishment")?
        };
        // `has_errors()` is the direct question. The old proxy — "is there something
        // pending to sign?" — only caught failures that produced an error response, and
        // reader-authentication failures were not among them.
        if validated_request.has_errors() {
            anyhow::bail!("there were errors processing request: {validated_request:?}");
        }
        Ok((session_manager, validated_request))
    }

    /// Prepare response with required elements.
    pub fn create_response(
        mut session_manager: device::SessionManager,
        requested_items: &RequestedItems,
        key: &p256::ecdsa::SigningKey,
    ) -> Result<Vec<u8>> {
        let permitted_items = [(
            DOC_TYPE.to_string(),
            [(NAMESPACE.to_string(), vec![AGE_OVER_21_ELEMENT.to_string()])]
                .into_iter()
                .collect(),
        )]
        .into_iter()
        .collect();
        session_manager.prepare_response(requested_items, permitted_items);
        let (_, sign_payload) = session_manager.get_next_signature_payload().unwrap();
        let signature: p256::ecdsa::Signature = key.sign(sign_payload);
        session_manager
            .submit_next_signature(signature.to_vec())
            .context("failed to submit signature")?;
        session_manager
            .retrieve_response()
            .ok_or(anyhow!("cannot prepare response"))
    }

    /// Prepare response with required elements using COSE_Mac0 device authentication.
    ///
    /// Uses the static mdoc authentication key (SDeviceKey) for EMacKey derivation per
    /// ISO 18013-5 §9.1.3.5.
    pub fn create_response_mac0(
        mut session_manager: device::SessionManager,
        requested_items: &RequestedItems,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> Result<Vec<u8>> {
        let static_scalar: p256::NonZeroScalar = p256::SecretKey::from(signing_key.clone()).into();
        let e_mac_key = session_manager
            .e_mac_key_from_static_key(&static_scalar)
            .context("failed to derive EMacKey")?;
        let permitted_items = [(
            DOC_TYPE.to_string(),
            [(NAMESPACE.to_string(), vec![AGE_OVER_21_ELEMENT.to_string()])]
                .into_iter()
                .collect(),
        )]
        .into_iter()
        .collect();
        session_manager.set_device_auth_type(DeviceAuthType::Mac0);
        session_manager.prepare_response(requested_items, permitted_items);
        while let Some((_, payload)) = session_manager
            .get_next_signature_payload()
            .map(|(id, p)| (id, p.to_vec()))
        {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&e_mac_key).context("failed to create HMAC")?;
            mac.update(&payload);
            session_manager
                .submit_next_signature(mac.finalize().into_bytes().to_vec())
                .context("failed to submit MAC0 tag")?;
        }
        session_manager
            .retrieve_response()
            .ok_or(anyhow!("cannot retrieve response"))
    }

    /// Load the device signing key that matches the public key embedded in the test mDL's MSO.
    pub fn create_signing_key() -> Result<p256::ecdsa::SigningKey> {
        let der = base64::decode(include_str!("../test/issuance/device_key.b64").trim())?;
        Ok(p256::SecretKey::from_sec1_der(&der)?.into())
    }
}

pub struct Reader {}

impl Reader {
    /// Reader Processing mDL data.
    pub async fn reader_handle_device_response(
        reader_sm: &mut reader::SessionManager,
        response: Vec<u8>,
    ) -> Result<()> {
        // Use () to skip CRL checks in tests
        let validated = reader_sm
            .handle_response(&response, &AnyDocType(MdocProfile::MDL), &())
            .await;
        println!("Validated Response: {validated:?}");

        // This is a protocol-shape test. The reader here is configured with an empty
        // `TrustAnchorRegistry`, and the committed mDL fixture could not chain anyway:
        // its signing certificate is expired and missing SKI, EKU, KeyUsage,
        // CRLDistributionPoints and IssuerAltName. So the document is evaluated and
        // reported as untrusted, which is exactly what should happen.
        //
        // Real device-authentication coverage lives in `src/presentation/mod.rs`'s
        // `fully_trusted_exchange_reports_no_errors` and its MAC0 sibling, which mint
        // their own PKI — something an integration test cannot do, since `tests/` links
        // the library without `cfg(test)`.
        assert_eq!(validated.failed.len(), 1, "{validated:?}");
        let document = &validated.failed[0];

        assert!(
            document
                .errors
                .contains(&DocumentError::NoTrustAnchorsConfigured),
            "{:?}",
            document.errors
        );
        // Device authentication is not attempted: the device key lives in the MSO, and
        // an unverified MSO's device key proves nothing.
        assert!(
            document
                .errors
                .iter()
                .any(|e| matches!(e, DocumentError::DeviceAuthenticationNotAttempted { .. })),
            "{:?}",
            document.errors
        );

        // Nothing unsolicited came back, and the mDL was not rejected by the doc-type
        // filter the reader session now applies.
        assert!(validated.rejected.is_empty(), "{:?}", validated.rejected);

        // The point of the exchange: the requested element actually came back, and is
        // reported even though the credential could not be authenticated.
        assert_eq!(document.claimed_doc_type, DOC_TYPE);
        assert_eq!(
            document.namespaces[NAMESPACE][AGE_OVER_21_ELEMENT],
            serde_json::json!(true)
        );
        Ok(())
    }
}
