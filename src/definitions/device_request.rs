use crate::cbor::CborValue;
use crate::cose::sign1::CoseSign1;
use crate::definitions::helpers::{NonEmptyMap, NonEmptyVec, Tag24};
use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use isomdl_macros::FieldsNames;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type ItemsRequestBytes = Tag24<ItemsRequest>;
pub type DocType = String;
pub type NameSpace = String;
pub type IntentToRetain = bool;
pub type DataElementIdentifier = String;
pub type DataElements = NonEmptyMap<DataElementIdentifier, IntentToRetain>;
pub type Namespaces = NonEmptyMap<NameSpace, DataElements>;
pub type ReaderAuth = CoseSign1;

/// Represents a device request.
#[derive(Clone, Debug, FieldsNames)]
#[isomdl(rename_all = "camelCase")]
pub struct DeviceRequest {
    /// The version of the device request.
    pub version: String,

    /// A non-empty vector of document requests.
    pub doc_requests: NonEmptyVec<DocRequest>,
}

impl CborSerializable for DeviceRequest {}
impl AsCborValue for DeviceRequest {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "DeviceRequest is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(DeviceRequest {
            version: map
                .remove(&DeviceRequest::fn_version().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "version is missing".to_string()),
                ))?
                .into_text()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "version is not a string".to_string(),
                    ))
                })?,
            doc_requests: NonEmptyVec::from_cbor_value(
                map.remove(&DeviceRequest::fn_doc_requests().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, "doc_requests is missing".to_string()),
                    ))?
                    .into(),
            )?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let map = vec![
            (
                DeviceRequest::fn_version().into(),
                Value::Text(self.version),
            ),
            (
                Value::Text(DeviceRequest::fn_doc_requests().to_string()),
                self.doc_requests.to_cbor_value()?,
            ),
        ];
        Ok(Value::Map(map))
    }
}

/// Represents a document request.
#[derive(Clone, Debug, FieldsNames)]
#[isomdl(rename_all = "camelCase")]
pub struct DocRequest {
    /// The items request for the document.
    pub items_request: ItemsRequestBytes,

    /// The reader authentication, if provided.
    #[isomdl(skip_serializing_if = "Option::is_none")]
    pub reader_auth: Option<ReaderAuth>,
}

impl CborSerializable for DocRequest {}
impl AsCborValue for DocRequest {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut value = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "DocRequest is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(DocRequest {
            items_request: {
                ItemsRequestBytes::from_cbor_value(
                    value
                        .remove(&DocRequest::fn_items_request().into())
                        .ok_or(coset::CoseError::DecodeFailed(
                            ciborium::de::Error::Semantic(
                                None,
                                "items_request is missing".to_string(),
                            ),
                        ))?
                        .into(),
                )?
            },
            reader_auth: value
                .remove(&DocRequest::fn_reader_auth().into())
                .map(|v| {
                    ReaderAuth::from_cbor_value(v.into()).map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "reader_auth is not a CoseSign1".to_string(),
                        ))
                    })
                })
                .transpose()?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![];
        map.push((
            DocRequest::fn_items_request().into(),
            self.items_request.to_cbor_value()?,
        ));
        if let Some(reader_auth) = self.reader_auth {
            map.push((
                DocRequest::fn_reader_auth().into(),
                reader_auth.to_cbor_value()?,
            ));
        }
        Ok(Value::Map(map))
    }
}

/// Represents a request for items.
#[derive(Clone, Debug, FieldsNames, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[isomdl(rename_all = "camelCase")]
pub struct ItemsRequest {
    /// The type of document.
    pub doc_type: DocType,

    /// The namespaces associated with the request.
    #[serde(rename = "nameSpaces")]
    #[isomdl(rename = "nameSpaces")]
    pub namespaces: Namespaces,

    /// Additional information for the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[isomdl(skip_serializing_if = "Option::is_none")]
    pub request_info: Option<BTreeMap<String, CborValue>>,
}

impl CborSerializable for ItemsRequest {}
impl AsCborValue for ItemsRequest {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map: BTreeMap<CborValue, CborValue> = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "DeviceKeyInfo is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        Ok(ItemsRequest {
            doc_type: map
                .remove(&ItemsRequest::fn_doc_type().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(None, "doc_type is missing".to_string()),
                ))?
                .into_text()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "doc_type is missing".to_string(),
                    ))
                })?,
            namespaces: {
                map.remove(&ItemsRequest::fn_namespaces().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, "namespaces is missing".to_string()),
                    ))?
                    // Namespaces
                    .into_map()
                    .map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "namespaces is not a map".to_string(),
                        ))
                    })?
                    .into_iter()
                    .map(|(k, v)| {
                        Ok((
                            // NameSpace
                            k.into_text().map_err(|_| {
                                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                    None,
                                    "namespace key is not a string".to_string(),
                                ))
                            })?,
                            // DataElements
                            v.into_map()
                                .map_err(|_| {
                                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                        None,
                                        "namespace value is not a map".to_string(),
                                    ))
                                })?
                                .into_iter()
                                .map(|(key, v)| {
                                    Ok((
                                        // DataElementIdentifier
                                        key.into_text().map_err(|_| {
                                            coset::CoseError::DecodeFailed(
                                                ciborium::de::Error::Semantic(
                                                    None,
                                                    "data element key is not a string".to_string(),
                                                ),
                                            )
                                        })?,
                                        // IntentToRetain
                                        v.into_bool().map_err(|_| {
                                            coset::CoseError::DecodeFailed(
                                                ciborium::de::Error::Semantic(
                                                    None,
                                                    "data element value is not a bool".to_string(),
                                                ),
                                            )
                                        })?,
                                    ))
                                })
                                .collect::<coset::Result<DataElements>>()?,
                        ))
                    })
                    .collect::<coset::Result<Namespaces>>()?
            },
            request_info: map
                .remove(&ItemsRequest::fn_request_info().into())
                .map(|v| {
                    v.into_map()
                        .map_err(|_| {
                            coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                None,
                                "request_info is not a map".to_string(),
                            ))
                        })?
                        .into_iter()
                        .map(|(k, v)| {
                            Ok((
                                k.into_text().map_err(|_| {
                                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                                        None,
                                        "request_info key is not a string".to_string(),
                                    ))
                                })?,
                                v,
                            ))
                        })
                        .collect::<coset::Result<BTreeMap<String, CborValue>>>()
                })
                .transpose()?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![];
        map.push((
            Value::Text(ItemsRequest::fn_doc_type().to_string()),
            Value::Text(self.doc_type),
        ));
        map.push((Value::Text(ItemsRequest::fn_namespaces().to_string()), {
            let mut map = vec![];
            for (k, v) in self.namespaces.into_inner() {
                let mut map2 = vec![];
                for (k2, v2) in v.into_inner() {
                    map2.push((Value::Text(k2), Value::Bool(v2)));
                }
                map.push((Value::Text(k), Value::Map(map2)));
            }
            Value::Map(map)
        }));
        if let Some(request_info) = self.request_info {
            let mut map2 = vec![];
            for (k, v) in request_info {
                map2.push((Value::Text(k), v.into()));
            }
            map.push((
                Value::Text(ItemsRequest::fn_request_info().to_string()),
                Value::Map(map2),
            ));
        }
        Ok(Value::Map(map))
    }
}

impl DeviceRequest {
    pub const VERSION: &'static str = "1.0";
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn items_request() {
        const HEX: &str = "D8185868A267646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6A6E616D65537061636573A1716F72672E69736F2E31383031332E352E31A36B66616D696C795F6E616D65F46A676976656E5F6E616D65F46F646F63756D656E745F6E756D626572F4";
        let bytes: Vec<u8> = hex::decode(HEX).unwrap();
        let req = Tag24::<ItemsRequest>::from_slice(&bytes).unwrap();
        let roundtripped = req.to_vec().unwrap();
        assert_eq!(bytes, roundtripped);
    }

    #[test]
    fn doc_request() {
        const HEX: &str = "A16C6974656D7352657175657374D8185868A267646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6A6E616D65537061636573A1716F72672E69736F2E31383031332E352E31A36B66616D696C795F6E616D65F46A676976656E5F6E616D65F46F646F63756D656E745F6E756D626572F4";
        let bytes: Vec<u8> = hex::decode(HEX).unwrap();
        let req = DocRequest::from_slice(&bytes).unwrap();
        let roundtripped = req.to_vec().unwrap();
        assert_eq!(bytes, roundtripped);
    }

    #[test]
    fn device_request() {
        const HEX: &str = "A26776657273696F6E63312E306B646F63526571756573747381A16C6974656D7352657175657374D8185868A267646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6A6E616D65537061636573A1716F72672E69736F2E31383031332E352E31A36B66616D696C795F6E616D65F46A676976656E5F6E616D65F46F646F63756D656E745F6E756D626572F4";
        let bytes: Vec<u8> = hex::decode(HEX).unwrap();
        let req = DeviceRequest::from_slice(&bytes).unwrap();
        let roundtripped = req.to_vec().unwrap();
        assert_eq!(bytes, roundtripped);
    }
}
