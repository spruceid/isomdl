use std::borrow::{Borrow, BorrowMut};
use std::ops::{Deref, DerefMut};

use coset::{AsCborValue, iana, TaggedCborSerializable};

use crate::cose::serialized_as_cbor_value::SerializedAsCborValue;

pub mod mac0;
mod serialized_as_cbor_value;
pub mod sign1;

/// Trait to represent the signature algorithm of a signer or verifier.
pub trait SignatureAlgorithm {
    fn algorithm(&self) -> iana::Algorithm;
}

#[derive(Debug, Clone)]
pub struct MaybeTagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    pub tagged: bool,
    pub inner: T,
}

impl<T> MaybeTagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    pub fn new(tagged: bool, inner: T) -> Self {
        Self { tagged, inner }
    }
}

impl<T> Deref for MaybeTagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for MaybeTagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> Borrow<T> for MaybeTagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    fn borrow(&self) -> &T {
        &self.inner
    }
}

impl<T> BorrowMut<T> for MaybeTagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T> AsRef<T> for MaybeTagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

/// Serialize manually using `ciborium::tag::Captured`, putting the tag if
/// necessary.
impl<T> serde::Serialize for MaybeTagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let tag = if self.tagged {
            Some(coset::CoseSign1::TAG)
        } else {
            None
        };

        ciborium::tag::Captured(tag, SerializedAsCborValue(&self.inner)).serialize(serializer)
    }
}

/// Deserialize manually using `ciborium::tag::Captured`, checking the tag.
impl<'de, T> serde::Deserialize<'de> for MaybeTagged<T>
where
    T: AsCborValue + TaggedCborSerializable + Clone,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ciborium::tag::Captured(tag, SerializedAsCborValue(inner)) =
            ciborium::tag::Captured::deserialize(deserializer)?;
        let tagged = match tag {
            Some(coset::CoseSign1::TAG) => true,
            Some(_) => return Err(serde::de::Error::custom("unexpected tag")),
            None => false,
        };

        Ok(Self { tagged, inner })
    }
}
