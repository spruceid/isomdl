use anyhow::ensure;
use ciborium::Value;
use coset::CoseSign1;
use serde::{Deserialize, Serialize};

use crate::{
    cose::MaybeTagged,
    definitions::{
        helpers::{ByteStr, NonEmptyMap, NonEmptyVec, Tag24},
        issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes},
        DigestId, IssuerSigned, IssuerSignedItem,
    },
};

pub type IssuerNamespacesDehydrated =
    NonEmptyMap<String, NonEmptyVec<IssuerSignedDehydratedItemBytes>>;
pub type IssuerSignedDehydratedItemBytes = Tag24<IssuerSignedItemDehydrated>;
pub type DataElementValueOrNil = Option<ciborium::Value>;

/// > The IssuerSignedDehydrated structure conveys one or more IssuerAuth structures linked to one
/// > NameSpacedData structure. A combination of NameSpacedData (see 8.1.1) and
/// > IssuerSignedDehydrated as part of an issuing protocol allows for issuing mdoc data with multiple
/// > MSOs and avoids sending data elements multiple times. The mdoc app must combine parts of the two
/// > structures as specified in 8.1.3. An issuing service can also send the full IssuerSigned structure multiple
/// > times without using IssuerSignedDehydrated structure.
///
/// See: ISO 23220-3 § 8.1.2 mdoc IssuerSignedDehydrated structure
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedDehydrated {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_identifier: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "nameSpaces",
        alias = "nameSpacesDehydrated",
        alias = "digestIdMapping"
    )]
    pub namespaces: Option<IssuerNamespacesDehydrated>,
    pub issuer_auth: MaybeTagged<CoseSign1>,
}

impl From<IssuerNamespacesDehydrated> for IssuerNamespaces {
    fn from(value: IssuerNamespacesDehydrated) -> Self {
        value
            .into_inner()
            .into_iter()
            .map(|(key, items)| (key, items.into()))
            .collect::<std::collections::BTreeMap<_, _>>()
            .try_into()
            // Safe to unwrap: input was NonEmptyMap, so output is non-empty
            .unwrap()
    }
}

impl IssuerSignedDehydrated {
    /// Combines the dehydrated issuer-signed structure with namespaced data to produce
    /// a fully hydrated `IssuerSigned` structure.
    ///
    /// This implements the combination logic specified in ISO 23220-3 § 8.1.3.
    ///
    /// > The mdoc app must combine IssuerSignedDehydrated with the data in NameSpacedData to produce
    /// > IssuerSigned. For this to work both the mdoc app (at presentation time) and the issuer (at MSO
    /// > construction time) must agree on the encoding of IssuerSignedItem. Both shall use canonical encoding
    /// > as defined in ISO/IEC 23220-4 section XYZ. The order of the keys in the IssuerSignedItem shall be
    /// > identical to the order in IssuerSignedItemDehydrated with the elementValue as last element.
    ///
    /// > NOTE The mdoc app as well as the issuing service can use CBOR libraries that preserve the order of maps when creating or
    /// > validating IssuerAuth data. This standard does not define the order of a resulting CBOR.
    /// > The hydration of IssuerSignedDehydrated should be done with the NameSpacedData with the
    /// > matching dataIdentifier. In the case where there is not exactly one matching NameSpacedData then
    /// > hydration shall fail.
    ///
    /// > NOTE If hydration fails, a typical behavior of an mdoc app would be to re-request the full credential data.
    ///
    /// See: ISO 23220-3 § 8.1.3 Generation of IssuerSigned structure
    pub fn combine_namespaced_data(
        mut self,
        namespace_data: &NameSpacedData,
    ) -> Result<IssuerSigned, anyhow::Error> {
        // > The hydration of IssuerSignedDehydrated should be done with the NameSpacedData with the
        // > matching dataIdentifier. In the case where there is not exactly one matching NameSpacedData then
        // > hydration shall fail.
        ensure!(
            self.data_identifier == namespace_data.data_identifier,
            "Issuer Signed Dehydrated data identifier must match the NameSpacedData data identifier, if it exists"
        );

        if let Some(namespaces) = &mut self.namespaces {
            for (namespace_name, elements) in namespaces.iter_mut() {
                let Some(data_items) = namespace_data.namespaces.get(namespace_name) else {
                    anyhow::bail!("namespace '{}' not found in namspaced data", namespace_name);
                };

                ensure!(
                    elements.len() == data_items.len(),
                    "namespace '{}' has {} elements but provision data has {}",
                    namespace_name,
                    elements.len(),
                    data_items.len()
                );

                for (element, datum) in elements.iter_mut().zip(data_items.iter()) {
                    ensure!(
                        element.inner.element_identifier == datum.name,
                        "element identifier mismatch in namespace '{}': expected '{}', found '{}'",
                        namespace_name,
                        element.inner.element_identifier,
                        datum.name
                    );

                    // > If DataElementValueOrNil is not nil in IssuerSignedItemDehydrated,
                    // > then the mdoc app must use the data element value given in the structure
                    // > when generating the IssuerSigned structure with the linked IssuerAuth structure.
                    //
                    // See: ISO 23220-3 § 8.1.2
                    if element.inner.element_value.is_none()
                        || element.inner.element_value == Some(Value::Null)
                    {
                        element.inner.element_value = Some(datum.value.clone());
                    }
                }
            }
        }

        Ok(IssuerSigned {
            namespaces: self.namespaces.map(Into::into),
            issuer_auth: self.issuer_auth,
        })
    }
}

/// Represents an item signed by the issuer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItemDehydrated {
    /// The ID of the digest used for signing.
    #[serde(rename = "digestID")]
    pub digest_id: DigestId,

    /// Random bytes associated with the signed item.
    pub random: ByteStr,

    /// The identifier of the element.
    pub element_identifier: String,

    /// The value of the element.
    pub element_value: DataElementValueOrNil,
}

impl From<IssuerSignedItemDehydrated> for IssuerSignedItem {
    fn from(value: IssuerSignedItemDehydrated) -> Self {
        Self {
            digest_id: value.digest_id,
            random: value.random,
            element_identifier: value.element_identifier,
            element_value: value.element_value.unwrap_or(Value::Null),
        }
    }
}

impl From<IssuerSignedDehydratedItemBytes> for IssuerSignedItemBytes {
    fn from(value: IssuerSignedDehydratedItemBytes) -> Self {
        // Re-serialize the inner value to update inner_bytes with the populated element values.
        // This is necessary because Tag24 serializes using inner_bytes, not inner.
        Tag24::new(value.inner.into()).expect("failed to re-serialize IssuerSignedItem")
    }
}

pub type NameSpacedDataElements = NonEmptyMap<String, NonEmptyVec<NameSpacedDataElement>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NameSpacedDataElement {
    pub name: String,
    pub value: ciborium::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NameSpacedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_identifier: Option<String>,
    #[serde(alias = "provisionedData")]
    pub namespaces: NameSpacedDataElements,
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::FromHex;

    const HEX_ISSUER_SIGNED_DEHYDRATED: &str =
        include_str!("../../test/definitions/issuer_signed_dehydrated.cbor");
    const HEX_NAMESPACED_DATA: &str = include_str!("../../test/definitions/namespaced_data.cbor");

    #[test]
    fn test_issuer_signed_dehydrated() {
        let cbor_encoded_issuer_signed_dehydrated =
            <Vec<u8>>::from_hex(HEX_ISSUER_SIGNED_DEHYDRATED)
                .expect("failed to decode hex auth data");

        let namespaced_data = <Vec<u8>>::from_hex(HEX_NAMESPACED_DATA)
            .expect("failed to decode hex provisioned data");

        let issuer_signed_dehdrated: IssuerSignedDehydrated =
            crate::cbor::from_slice(&cbor_encoded_issuer_signed_dehydrated)
                .expect("failed to parse issuer signed dehydrated");

        let no_data = issuer_signed_dehdrated
            .namespaces
            .clone()
            .expect("namespaces does not exist")
            .iter()
            .flat_map(|(_, value)| value.iter())
            .all(|item| {
                item.inner.element_value.is_none()
                    || item.inner.element_value == Some(ciborium::Value::Null)
            });

        assert!(no_data);

        let namespace_data: NameSpacedData =
            crate::cbor::from_slice(&namespaced_data).expect("failed to parse namespaced data");

        let issuer_signed = issuer_signed_dehdrated
            .combine_namespaced_data(&namespace_data)
            .expect("failed to combine namespaced data with issuer signed dehydrated");

        let has_data = issuer_signed
            .namespaces
            .expect("namespaces does not exist")
            .iter()
            .flat_map(|(_, value)| value.iter())
            .any(|item| item.inner.element_value != ciborium::Value::Null);

        assert!(has_data)
    }

    #[test]
    fn test_combine_fails_on_element_count_mismatch() {
        let cbor_encoded_issuer_signed_dehydrated =
            <Vec<u8>>::from_hex(HEX_ISSUER_SIGNED_DEHYDRATED)
                .expect("failed to decode hex auth data");

        let namespaced_data = <Vec<u8>>::from_hex(HEX_NAMESPACED_DATA)
            .expect("failed to decode hex provisioned data");

        let issuer_signed_dehydrated: IssuerSignedDehydrated =
            crate::cbor::from_slice(&cbor_encoded_issuer_signed_dehydrated)
                .expect("failed to parse issuer signed dehydrated");

        let mut namespace_data: NameSpacedData =
            crate::cbor::from_slice(&namespaced_data).expect("failed to parse namespaced data");

        // Remove an element to cause a count mismatch
        let (_, elements) = namespace_data
            .namespaces
            .iter_mut()
            .next()
            .expect("expected at least one namespace");

        let truncated: Vec<_> = elements.iter().skip(1).cloned().collect();
        *elements = NonEmptyVec::maybe_new(truncated).expect("expected non-empty vec after skip");

        let err = issuer_signed_dehydrated
            .combine_namespaced_data(&namespace_data)
            .expect_err("expected error due to element count mismatch");

        assert!(
            err.to_string().contains("elements but provision data has"),
            "unexpected error message: {}",
            err
        );
    }

    #[test]
    fn test_combine_fails_on_element_identifier_mismatch() {
        let cbor_encoded_issuer_signed_dehydrated =
            <Vec<u8>>::from_hex(HEX_ISSUER_SIGNED_DEHYDRATED)
                .expect("failed to decode hex auth data");

        let namespaced_data = <Vec<u8>>::from_hex(HEX_NAMESPACED_DATA)
            .expect("failed to decode hex provisioned data");

        let issuer_signed_dehydrated: IssuerSignedDehydrated =
            crate::cbor::from_slice(&cbor_encoded_issuer_signed_dehydrated)
                .expect("failed to parse issuer signed dehydrated");

        let mut namespace_data: NameSpacedData =
            crate::cbor::from_slice(&namespaced_data).expect("failed to parse namespaced data");

        // Modify the first element's name to cause an identifier mismatch
        let (_, elements) = namespace_data
            .namespaces
            .iter_mut()
            .next()
            .expect("expected at least one namespace");

        elements
            .iter_mut()
            .next()
            .expect("expected at least one element")
            .name = "wrong_identifier".to_string();

        let err = issuer_signed_dehydrated
            .combine_namespaced_data(&namespace_data)
            .expect_err("expected error due to element identifier mismatch");

        assert!(
            err.to_string().contains("element identifier mismatch"),
            "unexpected error message: {}",
            err
        );
    }
}
