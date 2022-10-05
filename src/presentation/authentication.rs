//! Mdoc authentication.
//!
//! 1. As part of mdoc response, mdl produces `DeviceAuth`, which is either a `DeviceSignature` or
//!    a `DeviceMac`.
//!
//! 2. The reader must authenticate that `DeviceKey` in the MSO is the key that generated the
//!    `DeviceAuth`.
//!
//! 3. The reader must authenticate that the `DeviceKey` is authorized by `KeyAuthorizations` to
//!    sign over the data elements present in `DeviceNameSpaces`.
