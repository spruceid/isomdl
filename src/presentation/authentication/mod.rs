use std::collections::BTreeMap;

use crate::presentation::device::RequestedItems;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Module containing functions to perform mdoc authentication.
pub mod mdoc;

/// The outcome of the holder device authenticating the device request.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct RequestAuthenticationOutcome {
    /// The requested items from the mDL namespace.
    pub items_request: RequestedItems,
    /// The common name from the certificate that signed this request, if available.
    /// This value can be used to display to the user who the reader is, however
    /// caution should be exercised if reader authentication was not successful.
    pub common_name: Option<String>,
    /// Outcome of reader authentication.
    pub reader_authentication: AuthenticationStatus,
    /// Errors that occurred during request processing.
    pub errors: Errors,
}

/// The outcome of the reader device authenticating the device response.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ResponseAuthenticationOutcome {
    /// The values sent back from the holder device, serialized as JSON.
    pub response: BTreeMap<String, Value>,
    /// Outcome of issuer authentication.
    pub issuer_authentication: AuthenticationStatus,
    /// Outcome of device authentication.
    pub device_authentication: AuthenticationStatus,
    /// Errors that occurred during response processing.
    pub errors: Errors,
}

/// The outcome of authenticity checks.
#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy)]
pub enum AuthenticationStatus {
    #[default]
    Unchecked,
    Invalid,
    Valid,
}

/// Errors that occur during request/response processing.
pub type Errors = BTreeMap<String, serde_json::Value>;
