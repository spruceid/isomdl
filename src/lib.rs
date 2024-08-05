//! [ISO/IEC DIS 18013-5](https://mobiledl-e5018.web.app/ISO_18013-5_E_draft.pdf) `mDL` implementation in Rust.
//!
//! It is intended
//! to be used
//! in creating apps for `Devices` and `Readers` that can interact with each other to exchange `mDL`
//! data.
//!
//! ## Simulated `Device` and `Reader` interaction
//!
//! Here are examples of how to use the library. You can see more in [examples](../examples) folder and read about in the dedicated [README](../examples/README.md).
//!
//! This example demonstrates a simulated device and reader interaction.
//! The reader requests the `age_over_21` element, and the device responds with that value.
//! The flow is something like this:
//!
//! ```text
//!    +---------------------+                                          +----------------------+
//!    |                     |                                          |                      |
//!    |                     |                                          |                      |
//!    |   Device            |                                          |   Reader             |
//!    |                     |                                          |                      |
//!    |                     |                                          |                      |
//!    +---------+-----------+                                          +----------+-----------+
//!              |                                                                 |
//!          Initialize session                                                    |
//!              |                                                                 |
//!              |                                                                 |
//! Create QR code engagement                                                      |
//!              |                                                                 |
//!              +-------------+                                                   |
//!              |             |                                                   |
//!              |             |                                                   |
//!              <-------------+                                                   |
//!              |                                                                 |
//!              |                        Send QR code                             |
//!              +----------------------------------------------------------------->
//!              |                                                                 |
//!              |                                                                 | Establish session
//!              |                                                                 +-----------+
//!              |                                                                 |           |
//!              |                                                                 |           |
//!              |                                                                 +-----------+
//!              |                  Request age_over_21                            |
//!              <-----------------------------------------------------------------+
//!              |                                                                 |
//!              |                                                                 |
//!              |                                                                 |
//!              |                 Send age_over_21                                |
//!              +----------------------------------------------------------------->
//!              |                                                                 |
//!              |                                                                 |
//!              |                                                                 | Process age_over_21
//!              |                                                                 +-----------+
//!              |                                                                 |           |
//!              |                                                                 |           |
//!              |                                                                 +-----------+
//!              |                                                                 |
//!              |                                                                 |
//!              |                                                                 |
//!              |                    Session finished                             |
//!              |                                                                 |
//! ```
//!
//! 1. **Device initialization and engagement:**
//!     - The device creates a `QR code` containing `DeviceEngagement` data, which includes its public key.
//!     - Internally:
//!         - The device initializes with the `mDL` data, private key, and public key.
//! 2. **Reader processing `QR code` and requesting needed fields:**
//!     - The reader processes the QR code and creates a request for the `age_over_21` element.
//!     - Internally:
//!         - Generates its private and public keys.
//!         - Initiates a key exchange, and generates the session keys.
//!         - The request is encrypted with the reader's session key.
//! 3. **Device accepting request and responding:**
//!     - The device receives the request and creates a response with the `age_over_21` element.
//!     - Internally:
//!         - Initiates the key exchange, and generates the session keys.
//!         - Decrypts the request with the reader's session key.
//!         - Parse and validate it creating error response if needed.
//!         - The response is encrypted with the device's session key.
//! 4. **Reader Processing mDL data:**
//!     - The reader processes the response and prints the value of the `age_over_21` element.
//!
//! ### Device perspective
//!
//! There are several states through which the device goes during the interaction:
//!
//! ```text
//!
//!                                                  +---------+
//!                                                  |         |
//!                                                  |         |
//!                                                  | User    |
//!                                                  |         |
//!                                                  |         |
//!                                                  +---+-----+
//!                                                      |
//!                                                      |
//! +----------------------------------------------------v--------------------------------------------------------------+
//! |                                              Device                                                               |
//! |                                                                                                                   |
//! |                                         +-------------------+                                                     |
//! |                                         |                   |                                                     |
//! |                                         |SessionManagerInit |                                                     |
//! |                                         |                   |                                                     |
//! |       +---------------------------------+                   +-------------+                                       |
//! |       |                                 |                   |             |                                       |
//! |       |                                 |                   |             |                                       |
//! |       |                                 +-------------------+             |                                       |
//! |       |                                                                   |                                       |
//! |       |                                                              qr_engagement                                |
//! |       |                                                                   |                                       |
//! |       |                                                                   |                                       |
//! |   qr_engagement                                                           |                                       |
//! |       |                                                                   |                                       |
//! |       |                                                        +----------v------------+                          |
//! |       |                                                        |                       |                          |
//! |       |                                                        | SessionManagerEngaged <-------------+            |
//! |       |                                             +----------+                       |             |            |
//! |       |                                             |          |                       |             |            |
//! |       |                                             |          +-----------------------+             |            |
//! |       |                                             |                                                |            |
//! |       |                                             |                                                |            |
//! |       |                                             |                                                |            |
//! |       |                                             |                                                |            |
//! |       |                                             |                                                |            |
//! |       |                                             |                                                |            |
//! |       |                                             |                                                |            |
//! |       |                               process_session_establishment                                  |            |
//! |       |                                             |                                                |            |
//! |       |      +--------------------------------------v----------------------------------+             |            |
//! |       |      |                                 SessionManager                          |             |            |
//! |       |      |                                                                         |             |            |
//! |       |      |                             +--------------------+                      |             |            |
//! |       |      |                             |                    |                      |             |            |
//! |       |      |     +-----------------------+ AwaitingRequest    <----------------+     |             |            |
//! |       |      |     |                       |                    |                |     |             |            |
//! |       |      |     |           +-----------+                    |                |     |             |            |
//! |       |      |prepare_response |           +--------------------+                |     |             |            |
//! |       |      |     |           |                                                 |     |             |            |
//! |       |      |     |           |                                                 |     |       establish_session  |
//! |       |      |     |           |                                                 |     |             |            |
//! |       |      |     |         handle_request                                      |     |             |            |
//! |       |      |     |           |                                                 |     |             |            |
//! |       |      |     |           |                                                 |     |             |            |
//! |       |      |  +--v-----------v--------+                           retrieve_response  |             |            |
//! |       |      |  |                       +---------                               |     |             |            |
//! |       |      |  |   Signing             |   get_next_signature_payload           |     |             |            |
//! |       |      |  |                       <---------                               |     |             |            |
//! |       |      |  +---------+-------------+                                        |     |             |            |
//! |       |      |            |                                                      |     |             |            |
//! |       |      |            |                                                      |     |             |            |
//! |       |      |            |                                                      |     |             |            |
//! |       |      |      submit_next_signature                                        |     |             |            |
//! |       |      |            |                                                      |     |             |            |
//! |       |      |            |                 +----------------------+             |     |             |            |
//! |       |      |            |                 |                      |             |     |             |            |
//! |       |      |            |                 |   ReadyToRespond     |             |     |             |            |
//! |       |      |            +----------------->                      +-------------+     |             |            |
//! |       |      |                              |                      |                   |             |            |
//! |       |      |                              +----------+-----------+                   |             |            |
//! |       |      |                                         |                               |             |            |
//! |       |      +-----------------------------------------+-------------------------------+             |            |
//! |       |                                          handle_response                                     |            |
//! +-------+------------------------------------------------+---------------------------------------------+------------+
//!         |                                                |                                             |
//!         |                                        +-------v-------+                                     |
//!         |                                        |  Reader       |                                     |
//!         |                                        |               |                                     |
//!         |                                        |               |                                     |
//!         +---------------------------------------->               +-------------------------------------+
//!                                                  |               |
//!                                                  |               |
//!                                                  |               |
//!                                                  +---------------+
//! ```
//!
//! The reader is simulated in `common`
//! module (you can find the complete code in `examples` directory), here we focus on the code from the
//! device perspective.
//!
//! #### Example
//!
//! ```ignore
#![doc = include_str!("../tests/on_simulated_device.rs")]
//! ```
//!
//! ### Reader perspective
//!
//! From the reader's perspective, the flow is simpler:
//!
//! ```text
//!             +--------+
//!             |        |
//!             |  User  |
//!             |        |
//!             +---+----+
//!                 |
//!                 |
//!             +---v-----+
//!             |         |
//!             | Device  |
//!   +---------+         |<----------------+
//!   |         |         |                 |
//!   |         |         |                 |
//!   |         +--+--^---+                 |
//!   |              |  |                   |
//!   |              |  | establish_session |
//!   |qr_engagement |  |                   |
//!   |              |  |                   | new_request
//!   |              |  |                   |
//! +-v--------------v--+-------------------+---+
//! |                  Reader                   |
//! |                                           |
//! | +--------------------+   handle_response  |
//! | |                    +---------------+    |
//! | | SessionManager     |               |    |
//! | |                    |<--------------+    |
//! | +--------------------+                    |
//! |                                           |
//! +-------------------------------------------+
//! ```
//!
//! Now the device is simulated in `common`
//! module (you can find the complete code in `examples` directory),
//! here we focus on the code from the
//! reader's perspective.
//! The code is considerably shorter.
//!
//! #### Example
//!
//! ```ignore
#![doc = include_str!("../tests/on_simulated_reader.rs")]
//! ```
pub use cose_rs;

pub mod definitions;
pub mod issuance;
pub mod presentation;

pub mod macros {
    pub use isomdl_macros::{FromJson, ToCbor};
}
