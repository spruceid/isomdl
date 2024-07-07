#![doc(test(attr(deny(warnings))))]
//! ISO/IEC DIS 18013-5 mDL implementation in Rust.
//!
//! # Examples
//!
//! This example demonstrates a simulated device and reader interaction.  
//! The reader requests the `age_over_21` element, and the device responds with that value.
//! The flow is as follows:
//!
//! 1. Device initialization and engagement:
//!     - The device creates a QR code containing `DeviceEngagement` data, which includes its public key.
//!     - Internally:
//!         - The device initializes with the mDL data, private key, and public key.
//! 2. Reader processing QR and requesting needed fields:
//!     - The reader processes the QR code and creates a request for the `age_over_21` element.
//!     - Internally:
//!         - Generates its private and public keys.
//!         - Initiates a key exchange, and generates the session keys.
//!         - The request is encrypted with the reader's session key.
//! 3. Device accepting request and responding:
//!     - The device receives the request and creates a response with the `age_over_21` element.
//!     - Internally:
//!         - Initiates the key exchange, and generates the session keys.
//!         - Decrypts the request with the reader's session key.
//!         - Parse and validate it creating error response if needed.
//!         - The response is encrypted with the device's session key.
//! 4. Reader Processing mDL data:
//!     - The reader processes the response and prints the value of the `age_over_21` element.
//! <!-- INCLUDE-RUST: examples/simulated_device_and_reader.rs -->
//! ```
//! use anyhow::{Context, Result};
//! use isomdl::definitions::device_request::{DataElements, DocType, Namespaces};
//! use isomdl::definitions::helpers::NonEmptyMap;
//! use isomdl::presentation::device::{Document, Documents, PermittedItems, RequestedItems};
//! use isomdl::presentation::{device, reader, Stringify};
//! use std::collections::BTreeMap;
//!
//! const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
//! const NAMESPACE: &str = "org.iso.18013.5.1";
//! const AGE_OVER_21_ELEMENT: &str = "age_over_21";
//!
//! fn main() -> Result<()> {
//!     let mdl_encoded = include_str!("../test/stringified-mdl.txt");
//!     // Parse the mDL
//!     let docs = parse_mdl(mdl_encoded)?;
//!
//!     // Device initialization and engagement
//!     let (device_sm_engaged, qr) = initialize_and_engage_device(docs)?;
//!
//!     // Reader processing QR and requesting needed fields
//!     let (mut reader_sm, session_request) = establish_reader_session(qr)?;
//!
//!     // Device accepting request and validating
//!     let (mut device_sm, requested_items) =
//!         device_accept_request(device_sm_engaged, session_request)?;
//!     // Propagate any errors
//!     if let Ok(Some(response)) = check_for_errors(&mut device_sm) {
//!         let res = reader_sm.handle_response(&response)?;
//!         println!("Reader: {res:?}");
//!         println!("Errors sent, terminating.");
//!         return Ok(());
//!     };
//!
//!     // Prepare response with required elements
//!     let response = prepare_device_response(&mut device_sm, requested_items)?;
//!
//!     // Reader Processing mDL data
//!     reader_handle_device_response(&mut reader_sm, response)?;
//!
//!     Ok(())
//! }
//!
//! /// Check if there were any errors and sign them if needed, returning the response error.
//! fn check_for_errors(device_sm: &mut device::SessionManager) -> Result<Option<Vec<u8>>> {
//!     while let Some(_to_sign) = device_sm.get_next_signature_payload() {
//!         // TODO: Implement actual signing mechanism
//!         device_sm
//!             .submit_next_signature(vec![1, 2, 3, 4, 5])
//!             .context("failed to submit signature")?;
//!     }
//!     Ok(device_sm.retrieve_response())
//! }
//!
//! /// Parse the mDL encoded string into a [Documents] object.
//! fn parse_mdl(encoded: &str) -> Result<NonEmptyMap<DocType, Document>> {
//!     let mdl = Document::parse(encoded.to_string()).context("could not parse mDL")?;
//!     let docs = Documents::new(DOC_TYPE.to_string(), mdl);
//!     Ok(docs)
//! }
//!
//! /// Creates a QR code containing `DeviceEngagement` data, which includes its public key.
//! fn initialize_and_engage_device(
//!     docs: Documents,
//! ) -> Result<(device::SessionManagerEngaged, String)> {
//!     device::SessionManagerInit::initialise(docs, None, None)
//!         .context("failed to initialize device")?
//!         .qr_engagement()
//! }
//!
//! /// Establishes the reader session from the given QR code and create request for needed elements.
//! fn establish_reader_session(qr: String) -> Result<(reader::SessionManager, Vec<u8>)> {
//!     let requested_elements = Namespaces::new(
//!         NAMESPACE.into(),
//!         DataElements::new(AGE_OVER_21_ELEMENT.to_string(), false),
//!     );
//!     let (reader_sm, session_request, _) =
//!         reader::SessionManager::establish_session(qr, requested_elements)
//!             .context("failed to establish reader session")?;
//!     Ok((reader_sm, session_request))
//! }
//!
//! /// The Device accepts request and validates it returning requested items.
//! fn device_accept_request(
//!     device_sm_engaged: device::SessionManagerEngaged,
//!     session_request: Vec<u8>,
//! ) -> Result<(device::SessionManager, RequestedItems)> {
//!     let (device_sm, items) = device_sm_engaged.process_session_establishment(
//!         serde_cbor::value::from_value(serde_cbor::from_slice(&session_request)?)
//!             .context("Failed to process session establishment")?,
//!     )?;
//!     Ok((device_sm, items))
//! }
//!
//! // Prepare response with required elements.
//! fn prepare_device_response(
//!     device_sm: &mut device::SessionManager,
//!     items: RequestedItems,
//! ) -> Result<Vec<u8>> {
//!     let mut permitted = PermittedItems::new();
//!     let mut fields = BTreeMap::new();
//!     fields.insert(NAMESPACE.to_string(), vec![AGE_OVER_21_ELEMENT.to_string()]);
//!     permitted.insert(DOC_TYPE.into(), fields);
//!
//!     device_sm.prepare_response(&items, permitted);
//!     while let Some((_, _to_sign)) = device_sm.get_next_signature_payload() {
//!         // TODO: Implement actual signing mechanism
//!         device_sm
//!             .submit_next_signature(vec![1, 2, 3, 4, 5])
//!             .context("failed to submit signature")?;
//!     }
//!     Ok(device_sm
//!         .retrieve_response()
//!         .ok_or(anyhow::anyhow!("failed to prepare response"))
//!         .unwrap())
//! }
//!
//! /// Reader Processing mDL data.
//! fn reader_handle_device_response(
//!     reader_sm: &mut reader::SessionManager,
//!     response: Vec<u8>,
//! ) -> Result<()> {
//!     let res = reader_sm.handle_response(&response)?;
//!     println!("{:?}", res);
//!     Ok(())
//! }
//! ```
pub use cose_rs;

pub mod definitions;
pub mod issuance;
pub mod presentation;

pub mod macros {
    pub use isomdl_macros::{FromJson, ToCbor};
}
