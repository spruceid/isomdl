use std::collections::{BTreeMap, HashMap};

use ciborium::Value;
use coset::AsCborValue;
use isomdl_macros::FieldsNames;
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, EnumString};
use thiserror::Error;

use crate::definitions::{
    helpers::{NonEmptyMap, NonEmptyVec},
    DeviceSigned, IssuerSigned,
};

/// Represents a device response.
#[derive(Clone, Debug, FieldsNames, Deserialize, Serialize)]
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
#[derive(Clone, Debug, FieldsNames, Deserialize, Serialize)]
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
        let mut fields = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "Document is not a map".to_string(),
                ))
            })?
            .into_iter()
            .flat_map(|f| match f.0 {
                Value::Text(s) => Ok::<(String, Value), coset::CoseError>((s, f.1)),
                _ => Err(coset::CoseError::UnexpectedItem(
                    "key",
                    "text for field in Document",
                )),
            })
            .collect::<HashMap<String, Value>>();
        Ok(Document {
            doc_type: if let Some(Value::Text(s)) = fields.remove(Document::doc_type()) {
                s
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "text for doc_type",
                ));
            },
            issuer_signed: IssuerSigned::from_cbor_value(
                fields
                    .remove(Document::issuer_signed())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, "issuer_signed is missing".to_string()),
                    ))?,
            )?,
            device_signed: DeviceSigned::from_cbor_value(
                fields
                    .remove(Document::device_signed())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, "device_signed is missing".to_string()),
                    ))?,
            )?,

            errors: if let Some(errors) = fields.remove(Document::errors()) {
                Some(cbor_value_to_errors(errors)?)
            } else {
                None
            },
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![
            (
                Value::Text(Document::doc_type().to_string()),
                Value::Text(self.doc_type),
            ),
            (
                Value::Text(Document::issuer_signed().to_string()),
                self.issuer_signed.to_cbor_value()?,
            ),
            (
                Value::Text(Document::device_signed().to_string()),
                self.device_signed.to_cbor_value()?,
            ),
        ];
        if let Some(errors) = self.errors {
            map.push((
                Value::Text(Document::errors().to_string()),
                errors_to_cbor_value(errors)?,
            ));
        }
        Ok(Value::Map(map))
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

#[derive(Clone, Debug, Deserialize, Serialize, EnumString, AsRefStr)]
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
        let fields = if let Value::Map(map) = value {
            map
        } else {
            return Err(coset::CoseError::UnexpectedItem(
                "value",
                "map for DeviceResponse",
            ));
        };
        let mut fields = fields
            .into_iter()
            .flat_map(|f| match f.0 {
                Value::Text(s) => Ok::<(String, Value), coset::CoseError>((s, f.1)),
                _ => Err(coset::CoseError::UnexpectedItem(
                    "key",
                    "text for field in DeviceResponse",
                )),
            })
            .collect::<HashMap<String, Value>>();
        Ok(DeviceResponse {
            version: if let Some(Value::Text(s)) = fields.remove(DeviceResponse::version()) {
                s
            } else {
                return Err(coset::CoseError::UnexpectedItem(
                    "value",
                    "text for version",
                ));
            },
            documents: if let Some(documents) = fields.remove(DeviceResponse::documents()) {
                Some(Documents::from_cbor_value(documents)?)
            } else {
                None
            },
            document_errors: if let Some(document_errors) =
                fields.remove(DeviceResponse::document_errors())
            {
                Some(cbor_value_to_document_errors(document_errors)?)
            } else {
                None
            },
            status: {
                let status: u64 = fields
                    .remove(DeviceResponse::status())
                    .ok_or(coset::CoseError::UnexpectedItem(
                        "value",
                        "integer for status",
                    ))?
                    .into_integer()
                    .map_err(|_| coset::CoseError::UnexpectedItem("value", "integer for status"))?
                    .try_into()
                    .map_err(|_| coset::CoseError::UnexpectedItem("value", "integer for status"))?;
                Status::try_from(status).map_err(|_| {
                    ciborium::de::Error::Semantic::<Status>(
                        None,
                        "invalid status value".to_string(),
                    )
                })?
            },
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![];
        map.push((
            Value::Text(DeviceResponse::version().to_string()),
            Value::Text(self.version),
        ));
        if let Some(documents) = self.documents {
            map.push((
                Value::Text(DeviceResponse::documents().to_string()),
                documents.to_cbor_value()?,
            ));
        }
        if let Some(document_errors) = self.document_errors {
            map.push((
                Value::Text(DeviceResponse::document_errors().to_string()),
                document_errors_to_cbor_value(document_errors)?,
            ));
        }
        map.push((
            Value::Text(DeviceResponse::status().to_string()),
            Value::Integer((self.status as u64).into()),
        ));
        Ok(Value::Map(map))
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

fn cbor_value_to_document_errors(val: Value) -> coset::Result<DocumentErrors> {
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
    use ciborium::Value;
    use coset::CborSerializable;
    use hex::FromHex;
    use isomdl_macros::CborSerializable;
    use serde::{Deserialize, Serialize};

    use crate::cose::sign1::CoseSign1;
    use crate::definitions::device_signed::{
        DeviceNamespaces, DeviceNamespacesBytes, DeviceSignedItems,
    };
    use crate::definitions::helpers::string_cbor::CborString;
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
        println!("cbor_bytes {:?}", hex::encode(&cbor_bytes));
        println!("roundtripped_bytes {:?}", hex::encode(&roundtripped_bytes));
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
            DeviceSignedItems::new(CborString::from("a"), Value::Text("b".to_string()));
        let mut device_namespaces = DeviceNamespaces::new();
        device_namespaces.insert(CborString::from("eu-dl"), device_signed_items);
        let namespaces = DeviceNamespacesBytes::new(device_namespaces).unwrap();

        let issuer_signed_item = IssuerSignedItem {
            digest_id: DigestId(0),
            random: ByteStr::from(vec![0, 1, 2, 3]),
            element_identifier: "a".to_string(),
            element_value: Value::Text("b".to_string()).into(),
        };
        let issuer_signed_item_bytes = IssuerSignedItemBytes::new(issuer_signed_item).unwrap();
        let issuer_signed_item_bytes_vec = NonEmptyVec::new(issuer_signed_item_bytes);
        let issuer_namespaces =
            IssuerNamespaces::new(CborString::from("a"), issuer_signed_item_bytes_vec);
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
        println!("{:?}", hex::encode(&bytes));
        let document = Document::from_slice(&bytes).unwrap();
        let bytes2 = document.to_vec().unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn macro_test() {
        #[derive(CborSerializable, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Test {
            a: ciborium::Value,
            #[serde(rename = "c")]
            b: ciborium::Value,
            c_d: ciborium::Value,
        }
        let test = Test {
            a: ciborium::Value::Text("".to_string()),
            b: ciborium::Value::Text("".to_string()),
            c_d: ciborium::Value::Text("".to_string()),
        };
        let bytes = test.to_vec().unwrap();
        let test = Test::from_slice(&bytes).unwrap();
        let bytes2 = test.to_vec().unwrap();
        assert_eq!(bytes, bytes2);
    }
}
