pub trait IntoRaw<T: Clone> {
    fn into_raw(self) -> T;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KnownOrRaw<TU: Clone, TK: IntoRaw<TU>> {
    Known(TK),
    Unknown(TU),
}

impl<TU: Clone, TK: IntoRaw<TU>> IntoRaw<TU> for KnownOrRaw<TU, TK> {
    fn into_raw(self) -> TU {
        match self {
            KnownOrRaw::Known(known) => known.into_raw(),
            KnownOrRaw::Unknown(raw) => raw,
        }
    }
}

impl<TU: Clone, TK: IntoRaw<TU> + TryFrom<TU>> From<TU> for KnownOrRaw<TU, TK> {
    fn from(raw: TU) -> Self {
        match TK::try_from(raw.clone()) {
            Ok(known) => KnownOrRaw::Known(known),
            Err(_) => KnownOrRaw::Unknown(raw),
        }
    }
}

/// Implement FromRaw and Into<Raw> for an enum that is represented by a raw value.
/// The enum must implement [`strum_macros::EnumIter`]
macro_rules! impl_partial_enum {
    ($enum_name:ty, $backing:ty) => {
        use crate::definitions::device_engagement::nfc::util;
        impl util::IntoRaw<$backing> for $enum_name {
            fn into_raw(self) -> $backing {
                self as $backing
            }
        }
        impl TryFrom<$backing> for $enum_name {
            type Error = ();
            fn try_from(raw: $backing) -> Result<Self, Self::Error> {
                use ::strum::IntoEnumIterator;
                match Self::iter().find(|&v| v.into_raw() == raw) {
                    Some(v) => Ok(v),
                    None => Err(()),
                }
            }
        }
    };
}

use std::fmt::Display;

pub(super) use impl_partial_enum;

pub struct DisplayBytesAsHex<'a>(&'a [u8]);
impl<'a> std::fmt::Debug for DisplayBytesAsHex<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl<'a> Display for DisplayBytesAsHex<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<'a> From<&'a [u8]> for DisplayBytesAsHex<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        DisplayBytesAsHex(bytes)
    }
}

#[derive(Clone)]
pub struct ByteVecDisplayAsHex(Vec<u8>);
impl std::fmt::Debug for ByteVecDisplayAsHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", DisplayBytesAsHex(&self.0))
    }
}

impl Display for ByteVecDisplayAsHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<Vec<u8>> for ByteVecDisplayAsHex {
    fn from(bytes: Vec<u8>) -> Self {
        ByteVecDisplayAsHex(bytes)
    }
}

impl From<&[u8]> for ByteVecDisplayAsHex {
    fn from(bytes: &[u8]) -> Self {
        ByteVecDisplayAsHex(bytes.to_vec())
    }
}
