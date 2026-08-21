pub mod revocation;
pub mod trust_anchor;
mod util;
pub mod validation;
pub mod x5chain;

pub use util::SupportedCurve;
pub use x5chain::{Builder, X5Chain};

/// Certificate fixtures shared by the x509, VICAL, issuance and presentation tests.
///
/// Not every helper has a caller in every build configuration, hence the blanket
/// `dead_code` allowance.
#[cfg(test)]
#[allow(dead_code)]
#[path = "tests.rs"]
pub(crate) mod test;
