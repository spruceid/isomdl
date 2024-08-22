use std::collections::BTreeMap;

use ciborium::Value;
use coset::AsCborValue;
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, EnumString, EnumVariantNames};
use thiserror::Error;

use crate::definitions::{
    helpers::{NonEmptyMap, NonEmptyVec},
    DeviceSigned, IssuerSigned,
};

/// Represents a device response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    /// The version of the response.
    pub version: String,

    /// The documents associated with the response, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Documents>,

    /// The errors associated with the documents, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_errors: Option<DocumentErrors>,

    /// The status of the response.
    pub status: Status,
}

pub type Documents = NonEmptyVec<Document>;

/// Represents a document.
///
/// This struct is used to store information about a document.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// A string representing the type of the document.
    pub doc_type: String,

    /// An instance of the [IssuerSigned] struct representing the issuer-signed data.
    pub issuer_signed: IssuerSigned,

    /// An instance of the [DeviceSigned] struct representing the device-signed data.
    pub device_signed: DeviceSigned,

    /// An optional instance of the [Errors] struct representing any errors associated with the document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Errors>,
}

impl coset::CborSerializable for Document {}
impl AsCborValue for Document {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut arr = if let Value::Array(arr) = value {
            arr
        } else {
            return Err(coset::CoseError::UnexpectedItem(
                "value",
                "array for Document",
            ));
        };
        Ok(Document {
            doc_type: if let Value::Text(s) = arr.remove(0) {
                s
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "text for doc_type",
                ));
            },
            issuer_signed: IssuerSigned::from_cbor_value(arr.remove(0))?,
            device_signed: DeviceSigned::from_cbor_value(arr.remove(0))?,

            errors: if let Some(errors) = arr.get(0).cloned() {
                Some(cbor_value_to_errors(errors)?)
            } else {
                None
            },
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut arr = vec![
            Value::Text(self.doc_type),
            self.issuer_signed.to_cbor_value()?,
            self.device_signed.to_cbor_value()?,
        ];
        if let Some(errors) = self.errors {
            arr.push(errors_to_cbor_value(errors)?);
        }
        Ok(Value::Array(arr))
    }
}

fn errors_to_cbor_value(val: Errors) -> coset::Result<Value> {
    Ok(Value::Map(
        val.into_inner()
            .into_iter()
            .map(|(k, v)| {
                (
                    Value::Text(k),
                    Value::Map(
                        v.into_inner()
                            .into_iter()
                            .flat_map(|(k, v)| {
                                Ok::<(Value, Value), coset::CoseError>((
                                    Value::Text(k),
                                    Value::Integer(
                                        match v {
                                            DocumentErrorCode::DataNotReturned => 0_i128,
                                            DocumentErrorCode::ApplicationSpecific(i) => i,
                                        }
                                        .try_into()
                                        .map_err(|_| coset::CoseError::EncodeFailed)?,
                                    ),
                                ))
                            })
                            .collect(),
                    ),
                )
            })
            .collect(),
    ))
}

fn cbor_value_to_errors(val: Value) -> coset::Result<Errors> {
    Ok(val
        .into_map()
        .map_err(|_| coset::CoseError::UnexpectedItem("value", "map for errors"))?
        .into_iter()
        .flat_map(|(k, v)| {
            // NonEmptyMap<String, NonEmptyMap<String, DocumentErrorCode>>
            let key = k
                .into_text()
                .map_err(|_| coset::CoseError::UnexpectedItem("value", "text"))?;
            let value = v
                .into_map()
                .map_err(|_| coset::CoseError::UnexpectedItem("value", "map"))?
                .into_iter()
                .flat_map(|(k, v)| {
                    // NonEmptyMap<String, DocumentErrorCode>>
                    let key = k
                        .into_text()
                        .map_err(|_| coset::CoseError::UnexpectedItem("value", "text"))?;
                    let value = v
                        .into_integer()
                        .map_err(|_| coset::CoseError::UnexpectedItem("value", "integer"))?
                        .try_into()
                        .map_err(|_| coset::CoseError::UnexpectedItem("value", "integer"))?;
                    let value = match value {
                        0 => DocumentErrorCode::DataNotReturned,
                        i => DocumentErrorCode::ApplicationSpecific(i),
                    };
                    Ok::<(String, DocumentErrorCode), coset::CoseError>((key, value))
                })
                .collect::<NonEmptyMap<String, DocumentErrorCode>>();
            Ok::<(String, NonEmptyMap<String, DocumentErrorCode>), coset::CoseError>((key, value))
        })
        .collect::<Errors>())
}

/// Errors mapped by namespace and element identifier.
pub type Errors = NonEmptyMap<String, NonEmptyMap<String, DocumentErrorCode>>;
/// A list of document errors.
pub type DocumentErrors = NonEmptyVec<DocumentError>;
/// A map of document type to document error for them.
pub type DocumentError = BTreeMap<String, DocumentErrorCode>;

/// Document specific errors.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "i128", into = "i128")]
pub enum DocumentErrorCode {
    DataNotReturned,
    ApplicationSpecific(i128),
}

#[derive(Clone, Debug, Deserialize, Serialize, EnumString, EnumVariantNames, AsRefStr)]
#[serde(try_from = "u64", into = "u64")]
pub enum Status {
    OK = 0,
    GeneralError = 1,
    CborDecodingError = 2,
    CborValidationError = 3,
}

#[derive(Clone, Debug, Error)]
pub enum Error {
    #[error("invalid status value")]
    InvalidValue(String),
}

impl TryFrom<i32> for Status {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Status::OK),
            1 => Ok(Status::GeneralError),
            2 => Ok(Status::CborDecodingError),
            3 => Ok(Status::CborValidationError),
            _ => Err(Error::InvalidValue(format!(
                "invalid status value: {}",
                value
            ))),
        }
    }
}

impl From<i128> for DocumentErrorCode {
    fn from(value: i128) -> Self {
        match value {
            0 => DocumentErrorCode::DataNotReturned,
            _ => DocumentErrorCode::ApplicationSpecific(value),
        }
    }
}

impl DeviceResponse {
    pub const VERSION: &'static str = "1.0";
}

impl coset::CborSerializable for DeviceResponse {}
impl AsCborValue for DeviceResponse {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut arr = value.into_array().map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "not an array".to_string(),
            ))
        })?;
        let version = arr
            .remove(0)
            .as_text()
            .ok_or(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "not an text".to_string()),
            ))?
            .to_string();
        let documents = if let Some(documents) = arr.get(0).cloned() {
            Some(Documents::from_cbor_value(documents)?)
        } else {
            None
        };
        let document_errors = if let Some(document_errors) = arr.get(0).cloned() {
            Some(cbor_value_to_document_errors(document_errors)?)
        } else {
            None
        };
        let status: i32 = arr
            .last()
            .ok_or(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "no status".to_string()),
            ))?
            .as_integer()
            .ok_or(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "not an text".to_string()),
            ))?
            .try_into()?;
        let status = Status::try_from(status).map_err(|_| {
            ciborium::de::Error::Semantic::<Status>(None, "invalid status value".to_string())
        })?;
        Ok(DeviceResponse {
            version,
            documents,
            document_errors,
            status,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut arr = vec![Value::Text(self.version)];
        if let Some(documents) = self.documents {
            arr.push(documents.to_cbor_value()?);
        }
        if let Some(document_errors) = self.document_errors {
            arr.push(document_errors_to_cbor_value(document_errors)?);
        }
        arr.push(Value::Integer((self.status as u64).into()));
        Ok(Value::Array(arr))
    }
}

impl From<DocumentErrorCode> for i128 {
    fn from(c: DocumentErrorCode) -> i128 {
        match c {
            DocumentErrorCode::DataNotReturned => 0,
            DocumentErrorCode::ApplicationSpecific(i) => i,
        }
    }
}

impl From<Status> for u64 {
    fn from(s: Status) -> u64 {
        match s {
            Status::OK => 0,
            Status::GeneralError => 10,
            Status::CborDecodingError => 11,
            Status::CborValidationError => 12,
        }
    }
}

impl TryFrom<u64> for Status {
    type Error = String;

    fn try_from(n: u64) -> Result<Status, String> {
        match n {
            0 => Ok(Status::OK),
            10 => Ok(Status::GeneralError),
            11 => Ok(Status::CborDecodingError),
            12 => Ok(Status::CborValidationError),
            _ => Err(format!("unrecognised error code: {n}")),
        }
    }
}

fn document_errors_to_cbor_value(docs: DocumentErrors) -> coset::Result<Value> {
    Ok(Value::Array(
        docs.into_inner()
            .into_iter()
            .map(|doc_err| {
                Value::Map(
                    doc_err
                        .into_iter()
                        .flat_map(|(k, v)| {
                            Ok::<(Value, Value), coset::CoseError>((
                                Value::Text(k),
                                Value::Integer(
                                    match v {
                                        DocumentErrorCode::DataNotReturned => 0_i128,
                                        DocumentErrorCode::ApplicationSpecific(i) => i,
                                    }
                                    .try_into()
                                    .map_err(|_| coset::CoseError::EncodeFailed)?,
                                ),
                            ))
                        })
                        .collect(),
                )
            })
            .collect(),
    ))
}

fn cbor_value_to_document_errors(val: ciborium::Value) -> coset::Result<DocumentErrors> {
    let arr = val.into_array().map_err(|_| {
        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
            None,
            "not an array".to_string(),
        ))
    })?;
    let mut docs = vec![];
    for doc_err in arr {
        let doc_err = doc_err.into_map().map_err(|_| {
            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                None,
                "not a map".to_string(),
            ))
        })?;
        let mut doc_err_map = BTreeMap::new();
        for (k, v) in doc_err {
            let k = k
                .as_text()
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "not a text".to_string()),
                ))?
                .to_string();
            let code: i128 = v
                .as_integer()
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "not an integer".to_string()),
                ))?
                .try_into()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "not an integer".to_string(),
                    ))
                })?;
            let v = if code == 0 {
                DocumentErrorCode::DataNotReturned
            } else {
                DocumentErrorCode::ApplicationSpecific(code)
            };
            doc_err_map.insert(k, v);
        }
        docs.push(doc_err_map);
    }
    let docs = DocumentErrors::maybe_new(docs).ok_or(ciborium::de::Error::Semantic::<
        DocumentErrors,
    >(None, "docs are empty".to_string()))?;
    Ok(docs)
}

#[cfg(test)]
mod test {
    use coset::CborSerializable;
    use hex::FromHex;

    use crate::cose::sign1::CoseSign1;
    use crate::definitions::device_signed::{
        DeviceNamespaces, DeviceNamespacesBytes, DeviceSignedItems,
    };
    use crate::definitions::helpers::{ByteStr, NonEmptyVec};
    use crate::definitions::issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes};
    use crate::definitions::{
        DeviceAuth, DeviceSigned, DigestId, Document, IssuerSigned, IssuerSignedItem,
    };

    use super::DeviceResponse;

    static DEVICE_RESPONSE_CBOR: &str = include_str!("../../test/definitions/device_response.cbor");

    #[test]
    fn serde_device_response() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(DEVICE_RESPONSE_CBOR).expect("unable to convert cbor hex to bytes");
        let response: DeviceResponse =
            serde_cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as a DeviceResponse");
        let roundtripped_bytes =
            serde_cbor::to_vec(&response).expect("unable to encode DeviceResponse as cbor bytes");
        assert_eq!(
            cbor_bytes, roundtripped_bytes,
            "original cbor and re-serialized DeviceResponse do not match"
        );
    }

    #[test]
    fn ciborium_device_response() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(DEVICE_RESPONSE_CBOR).expect("unable to convert cbor hex to bytes");
        let response: DeviceResponse = DeviceResponse::from_slice(&cbor_bytes)
            .expect("unable to decode cbor as a DeviceResponse");
        let roundtripped_bytes = response
            .to_vec()
            .expect("unable to encode DeviceResponse as cbor bytes");
        assert_eq!(
            cbor_bytes, roundtripped_bytes,
            "original cbor and re-serialized DeviceResponse do not match"
        );
    }

    #[test]
    fn ciborium_documents() {
        static COSE_SIGN1: &str = include_str!("../../test/definitions/cose/sign1/serialized.cbor");
        let cose_sign1 = CoseSign1::from_slice(&<Vec<u8>>::from_hex(COSE_SIGN1).unwrap()).unwrap();
        let device_signed_items =
            DeviceSignedItems::new("a".to_string(), serde_cbor::Value::Text("b".to_string()));
        let mut device_namespaces = DeviceNamespaces::new();
        device_namespaces.insert("eu-dl".to_string(), device_signed_items);
        let namespaces = DeviceNamespacesBytes::new(device_namespaces).unwrap();

        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId(0),
            random: ByteStr::from(vec![0, 1, 2, 3]),
            element_identifier: "a".to_string(),
            element_value: serde_cbor::Value::Text("b".to_string()),
        };
        let issuer_signed_item_bytes = IssuerSignedItemBytes::new(issuer_signed_item).unwrap();
        let issuer_signed_item_bytes_vec = NonEmptyVec::new(issuer_signed_item_bytes);
        let issuer_namespaces =
            IssuerNamespaces::new("a".to_string(), issuer_signed_item_bytes_vec);
        let document = Document {
            doc_type: "a".to_string(),
            issuer_signed: IssuerSigned {
                namespaces: Some(issuer_namespaces),
                issuer_auth: cose_sign1.clone(),
            },
            device_signed: DeviceSigned {
                namespaces,
                device_auth: DeviceAuth::Signature {
                    device_signature: cose_sign1,
                },
            },
            errors: None,
        };
        let bytes = document.to_vec().unwrap();
        let document: Document = Document::from_slice(&bytes).unwrap();
        let bytes2 = document.to_vec().unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn ciborium_issuer_signed() {
        static COSE_SIGN1: &str = include_str!("../../test/definitions/cose/sign1/serialized.cbor");
        let cose_sign1 = CoseSign1::from_slice(&<Vec<u8>>::from_hex(COSE_SIGN1).unwrap()).unwrap();

        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId(0),
            random: ByteStr::from(vec![0, 1, 2, 3]),
            element_identifier: "a".to_string(),
            element_value: serde_cbor::Value::Text("b".to_string()),
        };
        let issuer_signed_item_bytes = IssuerSignedItemBytes::new(issuer_signed_item).unwrap();
        let issuer_signed_item_bytes_vec = NonEmptyVec::new(issuer_signed_item_bytes);
        let issuer_namespaces =
            IssuerNamespaces::new("a".to_string(), issuer_signed_item_bytes_vec);
        let issuer_signed = IssuerSigned {
            namespaces: Some(issuer_namespaces),
            issuer_auth: cose_sign1.clone(),
        };

        let bytes = issuer_signed.to_vec().unwrap();
        eprintln!("{:?}", hex::encode(&bytes));
        let issuer_signed: IssuerSigned = IssuerSigned::from_slice(&bytes).unwrap();
        let bytes2 = issuer_signed.to_vec().unwrap();
        assert_eq!(bytes, bytes2);
    }
}
