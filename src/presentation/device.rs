use std::collections::BTreeMap;
use std::num::ParseIntError;

use ciborium::Value;
use coset::{AsCborValue, CborSerializable, CoseMac0Builder, CoseSign1Builder};
use isomdl_macros::FieldsNames;
use p256::FieldBytes;
use uuid::Uuid;

use session::SessionTranscript180135;

use crate::cbor::CborValue;
use crate::cose::mac0::PreparedCoseMac0;
use crate::cose::sign1::{CoseSign1, PreparedCoseSign1};
use crate::definitions::device_signed::DeviceAuthType;
use crate::definitions::helpers::b_tree_map_string_cbor::BTreeMapCbor;
use crate::definitions::helpers::string_cbor::CborString;
use crate::definitions::IssuerSignedItem;
use crate::{
    definitions::{
        device_engagement::{DeviceRetrievalMethod, Security, ServerRetrievalMethods},
        device_request::{DeviceRequest, DocRequest, ItemsRequest},
        device_response::{
            Document as DeviceResponseDoc, DocumentError, DocumentErrorCode, DocumentErrors,
            Errors as NamespaceErrors, Status,
        },
        device_signed::{DeviceAuth, DeviceAuthentication, DeviceNamespacesBytes, DeviceSigned},
        helpers::{tag24, NonEmptyMap, NonEmptyVec, Tag24},
        issuer_signed::{IssuerSigned, IssuerSignedItemBytes},
        session::{
            self, derive_session_key, get_shared_secret, Handover, SessionData, SessionTranscript,
        },
        CoseKey, DeviceEngagement, DeviceResponse, Mso, SessionEstablishment,
    },
    issuance::Mdoc,
};

/// Initialisation state.
///
/// You enter this state using [SessionManagerInit::initialise] method, providing
/// the documents and optional non-empty list of device [DeviceRetrievalMethod] and
/// server [ServerRetrievalMethods] retrieval methods.
///
/// The [SessionManagerInit] state is restricted to creating a QR-code engagement,
/// using the [SessionManagerInit::qr_engagement] method, which will return the
/// [SessionManagerEngaged] Session Manager state.
///
/// For convenience, the [SessionManagerInit] state surfaces the [SessionManagerInit::ble_ident] method
/// to provide the BLE identification string for the device.
#[derive(Clone, FieldsNames)]
pub struct SessionManagerInit {
    documents: Documents,
    e_device_key: Vec<u8>,
    device_engagement: Tag24<DeviceEngagement>,
}

impl CborSerializable for SessionManagerInit {}
impl AsCborValue for SessionManagerInit {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "SessionManagerInit is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();

        Ok(SessionManagerInit {
            documents: Documents::from_cbor_value(
                map.remove(&SessionManagerInit::fn_documents().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "SessionManagerInit documents is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            e_device_key: map
                .remove(&SessionManagerInit::fn_e_device_key().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "SessionManagerInit e_device_key is missing".to_string(),
                    ),
                ))?
                .into_bytes()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManagerInit e_device_key is not a byte string".to_string(),
                    ))
                })?,
            device_engagement: Tag24::<DeviceEngagement>::from_cbor_value(
                map.remove(&SessionManagerInit::fn_documents().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "SessionManagerInit documents is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(
            vec![
                (
                    Value::Text(SessionManagerInit::fn_documents().to_string()),
                    self.documents.to_cbor_value()?,
                ),
                (
                    Value::Text(SessionManagerInit::fn_e_device_key().to_string()),
                    Value::Bytes(self.e_device_key),
                ),
                (
                    Value::Text(SessionManagerInit::fn_device_engagement().to_string()),
                    self.device_engagement.to_cbor_value()?,
                ),
            ]
            .into_iter()
            .collect(),
        ))
    }
}
/// Engaged state.
///
/// Transition to this state is made with [SessionManagerInit::qr_engagement].
/// That creates the `QR code` that the reader will use to establish the session.
#[derive(Clone, FieldsNames)]
pub struct SessionManagerEngaged {
    documents: Documents,
    e_device_key: Vec<u8>,
    device_engagement: Tag24<DeviceEngagement>,
    handover: Handover,
}

impl CborSerializable for SessionManagerEngaged {}
impl AsCborValue for SessionManagerEngaged {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "SessionManagerEngaged is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(SessionManagerEngaged {
            documents: Documents::from_cbor_value(
                map.remove(&SessionManagerEngaged::fn_documents().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "SessionManagerEngaged documents is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            e_device_key: map
                .remove(&SessionManagerEngaged::fn_e_device_key().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "SessionManagerEngaged e_device_key is missing".to_string(),
                    ),
                ))?
                .into_bytes()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManagerEngaged e_device_key is not a byte string".to_string(),
                    ))
                })?,
            device_engagement: Tag24::<DeviceEngagement>::from_cbor_value(
                map.remove(&SessionManagerEngaged::fn_device_engagement().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "SessionManagerEngaged device_engagement is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            handover: Handover::from_cbor_value(
                map.remove(&SessionManagerEngaged::fn_handover().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "SessionManagerEngaged handover is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(
            vec![
                (
                    Value::Text(SessionManagerEngaged::fn_documents().to_string()),
                    self.documents.to_cbor_value()?,
                ),
                (
                    Value::Text(SessionManagerEngaged::fn_e_device_key().to_string()),
                    Value::Bytes(self.e_device_key),
                ),
                (
                    Value::Text(SessionManagerEngaged::fn_device_engagement().to_string()),
                    self.device_engagement.to_cbor_value()?,
                ),
                (
                    Value::Text(SessionManagerEngaged::fn_handover().to_string()),
                    self.handover.to_cbor_value()?,
                ),
            ]
            .into_iter()
            .collect(),
        )
        .into())
    }
}

/// The initial state of the Session Manager.
///
/// The Session Manager contains the documents, ephemeral device key, and device engagement.
///
/// Create a new Session Manager using the [SessionManagerInit::initialise] method, providing
/// the documents and optional non-empty list of device [DeviceRetrievalMethod] and
/// server [ServerRetrievalMethods] retrieval methods.
///
/// The [SessionManagerInit] state is restricted to creating a QR-code engagement,
/// using the [SessionManagerInit::qr_engagement] method, which will return the
/// [SessionManagerEngaged] Session Manager state.
///
/// For convience, the [SessionManagerInit] state surfaces the [SessionManagerInit::ble_ident] method
/// to provide the BLE identification string for the device.
#[derive(Clone, FieldsNames)]
pub struct SessionManager {
    documents: Documents,
    session_transcript: SessionTranscript180135,
    sk_device: [u8; 32],
    device_message_counter: u32,
    sk_reader: [u8; 32],
    reader_message_counter: u32,
    state: State,
    device_auth_type: DeviceAuthType,
}

impl CborSerializable for SessionManager {}
impl AsCborValue for SessionManager {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "SessionManager is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(SessionManager {
            documents: Documents::from_cbor_value(
                map.remove(&SessionManager::fn_documents().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "SessionManager documents is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            session_transcript: SessionTranscript180135::from_cbor_value(
                map.remove(&SessionManager::fn_session_transcript().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "SessionManager session_transcript is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            sk_device: map
                .remove(&SessionManager::fn_sk_device().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "SessionManager sk_device is missing".to_string(),
                    ),
                ))?
                .into_bytes()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManager sk_device is not a byte string".to_string(),
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManager sk_device has an invalid size".to_string(),
                    ))
                })?,
            device_message_counter: map
                .remove(&SessionManager::fn_device_message_counter().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "SessionManager device_message_counter is missing".to_string(),
                    ),
                ))?
                .into_integer()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManager device_message_counter is not an integer".to_string(),
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManager device_message_counter has an invalid size".to_string(),
                    ))
                })?,
            sk_reader: map
                .remove(&SessionManager::fn_sk_reader().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "SessionManager sk_reader is missing".to_string(),
                    ),
                ))?
                .into_bytes()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManager sk_reader is not a byte string".to_string(),
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManager sk_reader has an invalid size".to_string(),
                    ))
                })?,
            reader_message_counter: map
                .remove(&SessionManager::fn_reader_message_counter().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "SessionManager reader_message_counter is missing".to_string(),
                    ),
                ))?
                .into_integer()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManager reader_message_counter is not an integer".to_string(),
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "SessionManager reader_message_counter has an invalid size".to_string(),
                    ))
                })?,
            state: State::from_cbor_value(
                map.remove(&SessionManager::fn_state().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "SessionManager state is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            device_auth_type: DeviceAuthType::from_cbor_value(
                map.remove(&SessionManager::fn_device_auth_type().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "SessionManager device_auth_type is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(vec![
            (
                Value::Text(SessionManager::fn_documents().to_string()),
                self.documents.to_cbor_value()?,
            ),
            (
                Value::Text(SessionManager::fn_session_transcript().to_string()),
                self.session_transcript.to_cbor_value()?,
            ),
            (
                Value::Text(SessionManager::fn_sk_device().to_string()),
                Value::Bytes(self.sk_device.to_vec()),
            ),
            (
                Value::Text(SessionManager::fn_device_message_counter().to_string()),
                Value::Integer(self.device_message_counter.into()),
            ),
            (
                Value::Text(SessionManager::fn_sk_reader().to_string()),
                Value::Bytes(self.sk_reader.to_vec()),
            ),
            (
                Value::Text(SessionManager::fn_reader_message_counter().to_string()),
                Value::Integer(self.reader_message_counter.into()),
            ),
            (
                Value::Text(SessionManager::fn_state().to_string()),
                self.state.to_cbor_value()?,
            ),
            (
                Value::Text(SessionManager::fn_device_auth_type().to_string()),
                self.device_auth_type.to_cbor_value()?,
            ),
        ]))
    }
}

/// The internal states of the [SessionManager].
#[derive(Clone, Debug, Default)]
pub enum State {
    /// This is the default one where the device is waiting for a request from the reader.
    #[default]
    AwaitingRequest,
    /// The device is signing the response. The response could be a document or an error.
    Signing(PreparedDeviceResponse),
    /// The device is ready to respond to the reader with a signed response.
    ReadyToRespond(Vec<u8>),
}

impl CborSerializable for State {}
impl AsCborValue for State {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        match value {
            Value::Text(t) if t == *"AwaitingRequest" => Ok(State::AwaitingRequest),
            Value::Map(mut map) if map.len() == 1 => match map.remove(0) {
                (k, v) if k == Value::Text("Signing".to_string()) => {
                    Ok(State::Signing(PreparedDeviceResponse::from_cbor_value(v)?))
                }
                (k, v) if k == Value::Text("ReadyToRespond".to_string()) => {
                    Ok(State::ReadyToRespond(v.into_bytes().map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "State ReadyToRespond is not a byte string".to_string(),
                        ))
                    })?))
                }
                _ => Err(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "State is not a text or an array".to_string(),
                    ),
                )),
            },
            _ => Err(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(None, "State is not a text or an array".to_string()),
            )),
        }
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(match self {
            State::AwaitingRequest => Value::Text("AwaitingRequest".to_string()),
            State::Signing(p) => Value::Map(
                vec![(Value::Text("Signing".to_string()), p.to_cbor_value()?)]
                    .into_iter()
                    .collect(),
            ),
            State::ReadyToRespond(v) => Value::Map(
                vec![(Value::Text("ReadyToRespond".to_string()), Value::Bytes(v))]
                    .into_iter()
                    .collect(),
            ),
        })
    }
}

/// Various errors that can occur during the interaction with the reader.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Unable to generate ephemeral key.
    #[error("unable to generate ephemeral key: {0}")]
    EKeyGeneration(session::Error),
    /// Error encoding value to CBOR.
    #[error("error encoding value to CBOR: {0}")]
    Tag24CborEncoding(tag24::Error),
    /// Unable to generate shared secret.
    #[error("unable to generate shared secret: {0}")]
    SharedSecretGeneration(anyhow::Error),
    /// Error encoding value to CBOR.
    #[error("error encoding value to CBOR: {0}")]
    CborEncoding(coset::CoseError),
    /// Session manager was used incorrectly.
    #[error("session manager was used incorrectly")]
    ApiMisuse,
    /// Could not parse age attestation claim.
    #[error("could not parse age attestation claim")]
    ParsingError(#[from] ParseIntError),
    /// `age_over` element identifier is malformed.
    #[error("age_over element identifier is malformed")]
    PrefixError,
}

/// The documents the device owns.
pub type Documents = NonEmptyMap<DocType, Document>;
type DocType = CborString;

/// Device-internal document datatype.
#[derive(Debug, Clone, FieldsNames)]
pub struct Document {
    pub id: Uuid,
    pub issuer_auth: CoseSign1,
    pub mso: Mso,
    pub namespaces: Namespaces,
}

impl CborSerializable for Document {}
impl AsCborValue for Document {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "Document is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(Document {
            id: Uuid::from_bytes(
                map.remove(&Document::fn_id().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, "Document id is missing".to_string()),
                    ))?
                    .into_bytes()
                    .map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "Document id is not a UUID".to_string(),
                        ))
                    })?
                    .try_into()
                    .map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "Document id has an invalid size".to_string(),
                        ))
                    })?,
            ),
            issuer_auth: CoseSign1::from_cbor_value(
                map.remove(&Document::fn_issuer_auth().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "Document issuer_auth is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            mso: Mso::from_cbor_value(
                map.remove(&Document::fn_mso().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "Document issuer_auth is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            namespaces: Namespaces::from_cbor_value(
                map.remove(&Document::fn_namespaces().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "Document issuer_auth is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(
            vec![
                (
                    Value::Text(Document::fn_id().to_string()),
                    Value::Bytes(self.id.as_bytes().to_vec()),
                ),
                (
                    Value::Text(Document::fn_issuer_auth().to_string()),
                    self.issuer_auth.to_cbor_value()?,
                ),
                (
                    Value::Text(Document::fn_mso().to_string()),
                    self.mso.to_cbor_value()?,
                ),
                (
                    Value::Text(Document::fn_namespaces().to_string()),
                    self.namespaces.to_cbor_value()?,
                ),
            ]
            .into_iter()
            .collect(),
        )
        .into())
    }
}

/// Stores the prepared response.
///
/// After the device parses the request from the reader,
/// If there were errors,
/// it will prepare a list of [DocumentErrors].
/// If there are documents to be signed,
/// it will keep a list of prepared documents
/// which needs to be signed with [SessionManager::get_next_signature_payload] and [SessionManager::submit_next_signature].
/// After those are signed, they are kept in a list of [DeviceResponseDoc]
#[derive(Debug, Clone, FieldsNames)]
pub struct PreparedDeviceResponse {
    prepared_documents: Vec<PreparedDocument>,
    signed_documents: Vec<DeviceResponseDoc>,
    document_errors: Option<DocumentErrors>,
    status: Status,
    device_auth_type: DeviceAuthType,
}

impl CborSerializable for PreparedDeviceResponse {}
impl AsCborValue for PreparedDeviceResponse {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "PreparedDeviceResponse is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(PreparedDeviceResponse {
            prepared_documents: map
                .remove(&PreparedDeviceResponse::fn_prepared_documents().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "PreparedDeviceResponse prepared_documents is missing".to_string(),
                    ),
                ))?
                .into_array()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "PreparedDeviceResponse prepared_documents is not an array".to_string(),
                    ))
                })?
                .into_iter()
                .map(|v| PreparedDocument::from_cbor_value(v.into()))
                .collect::<coset::Result<Vec<PreparedDocument>>>()?,
            signed_documents: map
                .remove(&PreparedDeviceResponse::fn_signed_documents().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "PreparedDeviceResponse signed_documents is missing".to_string(),
                    ),
                ))?
                .into_array()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "PreparedDeviceResponse signed_documents is not an array".to_string(),
                    ))
                })?
                .into_iter()
                .map(|v| DeviceResponseDoc::from_cbor_value(v.into()))
                .collect::<coset::Result<Vec<DeviceResponseDoc>>>()?,
            document_errors: map
                .remove(&PreparedDeviceResponse::fn_document_errors().into())
                .map(|v| DocumentErrors::from_cbor_value(v.into()))
                .transpose()?,
            status: {
                let v = map
                    .remove(&PreparedDeviceResponse::fn_status().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "PreparedDeviceResponse status is missing".to_string(),
                        ),
                    ))?
                    .into_integer()
                    .map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "PreparedDeviceResponse status is not an integer".to_string(),
                        ))
                    })?;
                (v as i32).try_into().map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "PreparedDeviceResponse status is not a string".to_string(),
                    ))
                })?
            },
            device_auth_type: DeviceAuthType::from_cbor_value(
                map.remove(&PreparedDeviceResponse::fn_device_auth_type().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "PreparedDeviceResponse device_auth_type is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![];
        map.push((
            Value::Text(PreparedDeviceResponse::fn_prepared_documents().to_string()),
            Value::Array(
                self.prepared_documents
                    .into_iter()
                    .map(|d| d.to_cbor_value())
                    .collect::<coset::Result<Vec<Value>>>()?,
            ),
        ));
        map.push((
            Value::Text(PreparedDeviceResponse::fn_signed_documents().to_string()),
            Value::Array(
                self.signed_documents
                    .into_iter()
                    .map(|d| d.to_cbor_value())
                    .collect::<coset::Result<Vec<Value>>>()?,
            ),
        ));
        if let Some(errors) = self.document_errors {
            map.push((
                Value::Text(PreparedDeviceResponse::fn_document_errors().to_string()),
                errors.to_cbor_value()?,
            ));
        }
        map.push((
            Value::Text(PreparedDeviceResponse::fn_status().to_string()),
            Value::Integer(
                (self.status as i32)
                    .try_into()
                    .map_err(|_| coset::CoseError::EncodeFailed)?,
            ),
        ));
        map.push((
            Value::Text(PreparedDeviceResponse::fn_device_auth_type().to_string()),
            self.device_auth_type.to_cbor_value()?,
        ));
        Ok(Value::Map(map))
    }
}

#[derive(Debug, Clone, FieldsNames)]
enum PreparedCose {
    Sign1(PreparedCoseSign1),
    Mac0(PreparedCoseMac0),
}

impl CborSerializable for PreparedCose {}
impl AsCborValue for PreparedCose {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "PreparedCose is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        if map.len() != 1 {
            return Err(coset::CoseError::DecodeFailed(
                ciborium::de::Error::Semantic(
                    None,
                    "PreparedCose is not a map with a single key".to_string(),
                ),
            ));
        }
        let (k, v) = map.into_iter().next().unwrap();
        Ok(match k {
            k if k == PreparedCose::fn_sign1().into() => {
                PreparedCose::Sign1(PreparedCoseSign1::from_cbor_value(v.into())?)
            }
            k if k == PreparedCose::fn_mac0().into() => {
                PreparedCose::Mac0(PreparedCoseMac0::from_cbor_value(v.into())?)
            }
            _ => {
                return Err(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "PreparedCose is not a map with a single key".to_string(),
                    ),
                ))
            }
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(Value::Map(match self {
            PreparedCose::Sign1(s) => vec![(
                Value::Text(PreparedCose::fn_sign1().to_string()),
                s.to_cbor_value()?,
            )],
            PreparedCose::Mac0(m) => vec![(
                Value::Text(PreparedCose::fn_mac0().to_string()),
                m.to_cbor_value()?,
            )],
        }))
    }
}

impl PreparedCose {
    fn signature_payload(&self) -> &[u8] {
        match self {
            PreparedCose::Sign1(inner) => inner.signature_payload(),
            PreparedCose::Mac0(inner) => inner.signature_payload(),
        }
    }
}

#[derive(Debug, Clone, FieldsNames)]
struct PreparedDocument {
    id: Uuid,
    doc_type: String,
    issuer_signed: IssuerSigned,
    device_namespaces: DeviceNamespacesBytes,
    prepared_cose: PreparedCose,
    errors: Option<NamespaceErrors>,
}

impl CborSerializable for PreparedDocument {}
impl AsCborValue for PreparedDocument {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        let mut map = value
            .into_map()
            .map_err(|_| {
                coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                    None,
                    "PreparedDocument is not a map".to_string(),
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<BTreeMap<CborValue, CborValue>>();
        Ok(PreparedDocument {
            id: Uuid::from_bytes(
                map.remove(&PreparedDocument::fn_id().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "PreparedDocument id is missing".to_string(),
                        ),
                    ))?
                    .into_bytes()
                    .map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "PreparedDocument id is not a UUID".to_string(),
                        ))
                    })?
                    .try_into()
                    .map_err(|_| {
                        coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                            None,
                            "PreparedDocument id has an invalid size".to_string(),
                        ))
                    })?,
            ),
            doc_type: map
                .remove(&PreparedDocument::fn_doc_type().into())
                .ok_or(coset::CoseError::DecodeFailed(
                    ciborium::de::Error::Semantic(
                        None,
                        "PreparedDocument doc_type is missing".to_string(),
                    ),
                ))?
                .into_text()
                .map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "PreparedDocument doc_type is not a string".to_string(),
                    ))
                })?,
            issuer_signed: IssuerSigned::from_cbor_value(
                map.remove(&PreparedDocument::fn_issuer_signed().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "PreparedDocument issuer_signed is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            device_namespaces: DeviceNamespacesBytes::from_cbor_value(
                map.remove(&PreparedDocument::fn_device_namespaces().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "PreparedDocument device_namespaces is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            prepared_cose: PreparedCose::from_cbor_value(
                map.remove(&PreparedDocument::fn_prepared_cose().into())
                    .ok_or(coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(
                            None,
                            "PreparedDocument prepared_cose is missing".to_string(),
                        ),
                    ))?
                    .into(),
            )?,
            errors: map
                .remove(&PreparedDocument::fn_errors().into())
                .map(|v| NamespaceErrors::from_cbor_value(v.into()))
                .transpose()?,
        })
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        let mut map = vec![
            (
                Value::Text(PreparedDocument::fn_id().to_string()),
                Value::Bytes(self.id.as_bytes().to_vec()),
            ),
            (
                Value::Text(PreparedDocument::fn_doc_type().to_string()),
                Value::Text(self.doc_type),
            ),
            (
                Value::Text(PreparedDocument::fn_issuer_signed().to_string()),
                self.issuer_signed.to_cbor_value()?,
            ),
            (
                Value::Text(PreparedDocument::fn_device_namespaces().to_string()),
                self.device_namespaces.to_cbor_value()?,
            ),
            (
                Value::Text(PreparedDocument::fn_prepared_cose().to_string()),
                self.prepared_cose.to_cbor_value()?,
            ),
        ];
        if let Some(errors) = self.errors {
            map.push((
                Value::Text(PreparedDocument::fn_errors().to_string()),
                errors.to_cbor_value()?,
            ));
        }
        Ok(Value::Map(map))
    }
}

/// Elements in a namespace.
type Namespaces = NonEmptyMap<Namespace, NonEmptyMap<ElementIdentifier, IssuerSignedItemBytes>>;
type Namespace = CborString;
type ElementIdentifier = CborString;

/// A list of the requested items by the reader.
pub type RequestedItems = Vec<ItemsRequest>;
/// The lis of items that are permitted to be shared grouped by document type and namespace.
pub type PermittedItems = BTreeMap<DocType, BTreeMap<Namespace, Vec<ElementIdentifier>>>;

impl SessionManagerInit {
    /// Initialise the SessionManager.
    ///
    /// This is the first transition in the flow interaction.
    /// Internally, it generates the ephemeral key and creates the device engagement.
    ///
    /// It transition to [SessionManagerInit] state.
    pub fn initialise(
        documents: Documents,
        device_retrieval_methods: Option<NonEmptyVec<DeviceRetrievalMethod>>,
        server_retrieval_methods: Option<ServerRetrievalMethods>,
    ) -> Result<Self, Error> {
        let (e_device_key, e_device_key_pub) =
            session::create_p256_ephemeral_keys().map_err(Error::EKeyGeneration)?;
        let e_device_key_bytes =
            Tag24::<CoseKey>::new(e_device_key_pub).map_err(Error::Tag24CborEncoding)?;
        let security = Security(1, e_device_key_bytes);

        let device_engagement = DeviceEngagement {
            version: "1.0".to_string(),
            security,
            device_retrieval_methods,
            server_retrieval_methods,
            protocol_info: None,
        };

        let device_engagement =
            Tag24::<DeviceEngagement>::new(device_engagement).map_err(Error::Tag24CborEncoding)?;

        Ok(Self {
            documents,
            e_device_key: e_device_key.to_bytes().to_vec(),
            device_engagement,
        })
    }

    pub fn ble_ident(&self) -> anyhow::Result<[u8; 16]> {
        super::calculate_ble_ident(&self.device_engagement.as_ref().security.1)
    }

    /// Begins the device engagement using **QR code**.
    ///
    /// The response contains the device's public key and engagement data.
    pub fn qr_engagement(self) -> anyhow::Result<(SessionManagerEngaged, String)> {
        let qr_code_uri = self.device_engagement.to_qr_code_uri()?;
        let sm = SessionManagerEngaged {
            documents: self.documents,
            device_engagement: self.device_engagement,
            e_device_key: self.e_device_key,
            handover: Handover::QR,
        };
        Ok((sm, qr_code_uri))
    }
}

impl SessionManagerEngaged {
    /// It transitions to [SessionManager] state
    /// by processing the [SessionEstablishment] received from the reader.
    ///
    /// Internally, it generates the session keys based on the calculated shared secret
    /// (using **Diffie–Hellman key exchange**).
    ///
    /// Along with transitioning to [SessionManagerEngaged] state,
    /// it returns the requested items by the reader.
    pub fn process_session_establishment(
        self,
        session_establishment: SessionEstablishment,
    ) -> anyhow::Result<(SessionManager, RequestedItems)> {
        let e_reader_key = session_establishment.e_reader_key;
        let session_transcript =
            SessionTranscript180135(self.device_engagement, e_reader_key.clone(), self.handover);
        let session_transcript_bytes =
            Tag24::new(session_transcript.clone()).map_err(Error::Tag24CborEncoding)?;

        let e_device_key = p256::SecretKey::from_bytes(FieldBytes::from_slice(&self.e_device_key))?;

        let shared_secret = get_shared_secret(e_reader_key.into_inner(), &e_device_key.into())
            .map_err(Error::SharedSecretGeneration)?;

        let sk_reader = derive_session_key(&shared_secret, &session_transcript_bytes, true)?.into();
        let sk_device =
            derive_session_key(&shared_secret, &session_transcript_bytes, false)?.into();

        let mut sm = SessionManager {
            documents: self.documents,
            session_transcript,
            sk_device,
            device_message_counter: 0,
            sk_reader,
            reader_message_counter: 0,
            state: State::AwaitingRequest,
            device_auth_type: DeviceAuthType::Sign1,
        };

        let requested_data = sm.handle_decoded_request(SessionData {
            data: Some(session_establishment.data),
            status: None,
        })?;

        Ok((sm, requested_data))
    }
}

impl SessionManager {
    fn parse_request(&self, request: &[u8]) -> Result<DeviceRequest, PreparedDeviceResponse> {
        let request = CborValue::from_slice(request).map_err(|_| {
            // tracing::error!("unable to decode DeviceRequest bytes as cbor: {}", error);
            PreparedDeviceResponse::empty(Status::CborDecodingError, self.device_auth_type)
        })?;

        DeviceRequest::from_cbor_value(request.into()).map_err(|_| {
            // tracing::error!("unable to validate DeviceRequest cbor: {}", error);
            PreparedDeviceResponse::empty(Status::CborValidationError, self.device_auth_type)
        })
    }

    fn validate_request(
        &self,
        request: DeviceRequest,
    ) -> Result<Vec<ItemsRequest>, PreparedDeviceResponse> {
        if request.version != DeviceRequest::VERSION {
            // tracing::error!(
            //     "unsupported DeviceRequest version: {} ({} is supported)",
            //     request.version,
            //     DeviceRequest::VERSION
            // );
            return Err(PreparedDeviceResponse::empty(
                Status::GeneralError,
                self.device_auth_type,
            ));
        }
        Ok(request
            .doc_requests
            .into_inner()
            .into_iter()
            .map(|DocRequest { items_request, .. }| items_request.into_inner())
            .collect())
    }

    /// When the device is ready to respond, it prepares the response specifying the permitted items.
    ///
    /// It changes the internal state to [State::Signing],
    /// and you need
    /// to call [SessionManager::get_next_signature_payload] and then [SessionManager::submit_next_signature]
    /// to sign the documents.
    ///
    /// # Example
    ///
    /// ```text
    /// session_manager.prepare_response(&requested_items, permitted_items);
    /// let (_, payload)) = session_manager.get_next_signature_payload()?;
    /// let signature = sign(&payload);
    /// session_manager.submit_next_signature(signature);
    /// ```
    pub fn prepare_response(&mut self, requests: &RequestedItems, permitted: PermittedItems) {
        let prepared_response = DeviceSession::prepare_response(self, requests, permitted);
        self.state = State::Signing(prepared_response);
    }

    fn handle_decoded_request(&mut self, request: SessionData) -> anyhow::Result<RequestedItems> {
        let data = request.data.ok_or_else(|| {
            anyhow::anyhow!("no mdoc requests received, assume session can be terminated")
        })?;
        let decrypted_request = session::decrypt_reader_data(
            &self.sk_reader.into(),
            data.as_ref(),
            &mut self.reader_message_counter,
        )
        .map_err(|e| anyhow::anyhow!("unable to decrypt request: {}", e))?;
        let request = match self.parse_request(&decrypted_request) {
            Ok(r) => r,
            Err(e) => {
                self.state = State::Signing(e);
                return Ok(Default::default());
            }
        };
        let request = match self.validate_request(request) {
            Ok(r) => r,
            Err(e) => {
                self.state = State::Signing(e);
                return Ok(Default::default());
            }
        };
        Ok(request)
    }

    /// Handle a new request from the reader.
    ///
    /// The request is expected to be a [CBOR](https://cbor.io)
    /// encoded [SessionData] and encrypted.
    /// It will parse and validate it.
    ///
    /// It returns the requested items by the reader.
    pub fn handle_request(&mut self, request: &[u8]) -> anyhow::Result<RequestedItems> {
        let session_data = SessionData::from_slice(request)?;
        self.handle_decoded_request(session_data)
    }

    /// When there are documents to be signed, it will return then next one for signing.
    ///
    /// After signed, you need to call [SessionManager::submit_next_signature].
    ///
    /// # Example
    ///
    /// ```ignore
    /// while let Some((_, payload)) = session_manager.get_next_signature_payload()? {
    ///     let signature = sign(&payload);
    ///     session_manager.submit_next_signature(signature);
    /// }
    /// ```
    pub fn get_next_signature_payload(&self) -> Option<(Uuid, &[u8])> {
        match &self.state {
            State::Signing(p) => p.get_next_signature_payload(),
            _ => None,
        }
    }

    /// Submit the externally signed signature for object
    /// returned by [SessionManager::get_next_signature_payload].
    ///
    /// After all documents are signed, you can call [SessionManager::retrieve_response]
    /// to get the response that can then be sent to the reader.
    ///
    /// # Example
    ///
    /// ```ignore
    /// while let Some((_, payload)) = session_manager.get_next_signature_payload()? {
    ///     let signature = sign(&payload);
    ///     session_manager.submit_next_signature(signature);
    /// }
    /// ```
    pub fn submit_next_signature(&mut self, signature: Vec<u8>) -> anyhow::Result<()> {
        if matches!(self.state, State::Signing(_)) {
            match std::mem::take(&mut self.state) {
                State::Signing(mut p) => {
                    p.submit_next_signature(signature);
                    if p.is_complete() {
                        let response = p.finalize_response();
                        let mut status: Option<session::Status> = None;
                        let response_bytes = response.to_vec()?;
                        let encrypted_response = session::encrypt_device_data(
                            &self.sk_device.into(),
                            &response_bytes,
                            &mut self.device_message_counter,
                        )
                        .unwrap_or_else(|_e| {
                            //tracing::warn!("unable to encrypt response: {}", e);
                            status = Some(session::Status::SessionEncryptionError);
                            Default::default()
                        });
                        let data = if status.is_some() {
                            None
                        } else {
                            Some(encrypted_response.into())
                        };
                        let session_data = SessionData { status, data };
                        let encoded_response = session_data.to_vec()?;
                        self.state = State::ReadyToRespond(encoded_response);
                    } else {
                        self.state = State::Signing(p)
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    /// Identifies if the response is ready.
    ///
    /// The internal state is [State::ReadyToRespond] in this returns `true`.
    pub fn response_ready(&self) -> bool {
        matches!(self.state, State::ReadyToRespond(_))
    }

    /// Retrieves the prepared response.
    ///
    /// Will return [Some] after all documents have been signed.
    /// In that case, it will return the response
    /// and change the internal state to [State::AwaitingRequest]
    /// where it can accept new a request from the reader.
    pub fn retrieve_response(&mut self) -> Option<Vec<u8>> {
        if self.response_ready() {
            // Replace the state with AwaitingRequest.
            let state = std::mem::take(&mut self.state);
            match state {
                State::ReadyToRespond(r) => Some(r),
                // Unreachable as the state variant has already been checked.
                _ => unreachable!(),
            }
        } else {
            None
        }
    }
}

impl PreparedDeviceResponse {
    fn empty(status: Status, device_auth_type: DeviceAuthType) -> Self {
        PreparedDeviceResponse {
            status,
            prepared_documents: Vec::new(),
            document_errors: None,
            signed_documents: Vec::new(),
            device_auth_type,
        }
    }

    /// Identifies that the response ready to be finalized.
    ///
    /// If `false`, then there are still items that need to be authorized.
    pub fn is_complete(&self) -> bool {
        self.prepared_documents.is_empty()
    }

    /// When there are documents to be signed, it will return then next one for signing.
    pub fn get_next_signature_payload(&self) -> Option<(Uuid, &[u8])> {
        self.prepared_documents
            .last()
            .map(|doc| (doc.id, doc.prepared_cose.signature_payload()))
    }

    /// Submit the externally signed signature for object
    /// returned by [PreparedDeviceResponse::get_next_signature_payload].
    pub fn submit_next_signature(&mut self, signature: Vec<u8>) {
        let signed_doc = match self.prepared_documents.pop() {
            Some(doc) => doc.finalize(signature),
            None => {
                //tracing::error!(
                //    "received a signature for finalizing when there are no more prepared docs"
                //);
                return;
            }
        };
        self.signed_documents.push(signed_doc);
    }

    /// Will finalize and prepare the device response.
    pub fn finalize_response(self) -> DeviceResponse {
        if !self.is_complete() {
            //tracing::warn!("attempt to finalize PreparedDeviceResponse before all prepared documents had been authorized");
            return PreparedDeviceResponse::empty(Status::GeneralError, self.device_auth_type)
                .finalize_response();
        }

        DeviceResponse {
            version: DeviceResponse::VERSION.into(),
            documents: self.signed_documents.try_into().ok(),
            document_errors: self.document_errors,
            status: self.status,
        }
    }
}

impl PreparedDocument {
    fn finalize(self, signature: Vec<u8>) -> DeviceResponseDoc {
        let Self {
            issuer_signed,
            device_namespaces,
            prepared_cose,
            errors,
            doc_type,
            ..
        } = self;
        let device_auth = match prepared_cose {
            PreparedCose::Sign1(inner) => DeviceAuth::Signature {
                device_signature: inner.finalize(signature),
            },
            PreparedCose::Mac0(inner) => DeviceAuth::Mac {
                device_mac: inner.finalize(signature),
            },
        };

        let device_signed = DeviceSigned {
            namespaces: device_namespaces,
            device_auth,
        };
        DeviceResponseDoc {
            doc_type,
            issuer_signed,
            device_signed,
            errors,
        }
    }
}

/// Keeps the device session data.
///
/// One implementation is [SessionManager].
pub trait DeviceSession {
    type ST: SessionTranscript;

    /// Get the device documents.
    fn documents(&self) -> &Documents;
    fn session_transcript(&self) -> Self::ST;
    fn device_auth_type(&self) -> DeviceAuthType;
    /// Prepare the response based on the requested items and permitted ones.
    fn prepare_response(
        &self,
        requests: &RequestedItems,
        permitted: PermittedItems,
    ) -> PreparedDeviceResponse {
        let mut prepared_documents: Vec<PreparedDocument> = Vec::new();
        let mut document_errors: Vec<DocumentError> = Vec::new();

        for (doc_type, namespaces) in filter_permitted(requests, permitted).into_iter() {
            let document = match self.documents().get(&doc_type) {
                Some(doc) => doc,
                None => {
                    // tracing::error!("holder owns no documents of type {}", doc_type);
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let signature_algorithm = match document
                .mso
                .device_key_info
                .device_key
                .signature_algorithm()
            {
                Some(alg) => alg,
                None => {
                    //tracing::error!(
                    //    "device key for document '{}' cannot perform signing",
                    //    document.id
                    //);
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };

            let mut issuer_namespaces: BTreeMapCbor<
                CborString,
                NonEmptyVec<IssuerSignedItemBytes>,
            > = Default::default();
            let mut errors: BTreeMap<CborString, NonEmptyMap<CborString, DocumentErrorCode>> =
                Default::default();

            for (namespace, elements) in namespaces.into_iter() {
                if let Some(issuer_items) = document.namespaces.get(&namespace) {
                    for element_identifier in elements.into_iter() {
                        if let Some(item) = issuer_items.get(&element_identifier) {
                            if let Some(returned_items) =
                                issuer_namespaces.get_mut(&namespace.clone().into())
                            {
                                returned_items.push(item.clone());
                            } else {
                                let returned_items = NonEmptyVec::new(item.clone());
                                issuer_namespaces.insert(namespace.clone().into(), returned_items);
                            }
                        } else if let Some(returned_errors) = errors.get_mut(&namespace) {
                            returned_errors
                                .insert(element_identifier, DocumentErrorCode::DataNotReturned);
                        } else {
                            let returned_errors = NonEmptyMap::new(
                                element_identifier,
                                DocumentErrorCode::DataNotReturned,
                            );
                            errors.insert(namespace.clone(), returned_errors);
                        }
                    }
                } else {
                    for element_identifier in elements.into_iter() {
                        if let Some(returned_errors) = errors.get_mut(&namespace) {
                            returned_errors
                                .insert(element_identifier, DocumentErrorCode::DataNotReturned);
                        } else {
                            let returned_errors = NonEmptyMap::new(
                                element_identifier,
                                DocumentErrorCode::DataNotReturned,
                            );
                            errors.insert(namespace.clone(), returned_errors);
                        }
                    }
                }
            }

            let device_namespaces = match Tag24::new(Default::default()) {
                Ok(dp) => dp,
                Err(_e) => {
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth = DeviceAuthentication::new(
                self.session_transcript(),
                doc_type.clone().into(),
                device_namespaces.clone(),
            );
            let device_auth = match Tag24::new(device_auth) {
                Ok(da) => da,
                Err(_e) => {
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth_bytes = match device_auth.to_vec() {
                Ok(dab) => dab,
                Err(_e) => {
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let header = coset::HeaderBuilder::new()
                .algorithm(signature_algorithm)
                .build();

            let prepared_cose = match self.device_auth_type() {
                DeviceAuthType::Sign1 => {
                    let cose_sign1_builder = CoseSign1Builder::new().protected(header);
                    let prepared_cose_sign1 = match PreparedCoseSign1::new(
                        cose_sign1_builder,
                        Some(&device_auth_bytes),
                        None,
                        true,
                    ) {
                        Ok(prepared) => prepared,
                        Err(_e) => {
                            let error: DocumentError =
                                [(doc_type, DocumentErrorCode::DataNotReturned)]
                                    .into_iter()
                                    .collect();
                            document_errors.push(error);
                            continue;
                        }
                    };
                    PreparedCose::Sign1(prepared_cose_sign1)
                }
                DeviceAuthType::Mac0 => {
                    let cose_mac0_builder = CoseMac0Builder::new().protected(header);
                    let prepared_cose_mac0 = match PreparedCoseMac0::new(
                        cose_mac0_builder,
                        Some(&device_auth_bytes),
                        None,
                        true,
                    ) {
                        Ok(prepared) => prepared,
                        Err(_e) => {
                            let error: DocumentError =
                                [(doc_type, DocumentErrorCode::DataNotReturned)]
                                    .into_iter()
                                    .collect();
                            document_errors.push(error);
                            continue;
                        }
                    };
                    PreparedCose::Mac0(prepared_cose_mac0)
                }
            };

            let prepared_document = PreparedDocument {
                id: document.id,
                doc_type: doc_type.into(),
                issuer_signed: IssuerSigned {
                    namespaces: issuer_namespaces.try_into().ok(),
                    issuer_auth: document.issuer_auth.clone(),
                },
                device_namespaces,
                prepared_cose,
                errors: errors.try_into().ok(),
            };
            prepared_documents.push(prepared_document);
        }
        PreparedDeviceResponse {
            prepared_documents,
            document_errors: document_errors.try_into().ok(),
            status: Status::OK,
            signed_documents: Vec::new(),
            device_auth_type: self.device_auth_type(),
        }
    }
}

impl DeviceSession for SessionManager {
    type ST = SessionTranscript180135;

    fn documents(&self) -> &Documents {
        &self.documents
    }

    fn session_transcript(&self) -> SessionTranscript180135 {
        self.session_transcript.clone()
    }

    fn device_auth_type(&self) -> DeviceAuthType {
        self.device_auth_type
    }
}

impl From<Mdoc> for Document {
    fn from(mdoc: Mdoc) -> Document {
        fn extract(
            v: NonEmptyVec<IssuerSignedItemBytes>,
        ) -> NonEmptyMap<ElementIdentifier, IssuerSignedItemBytes> {
            v.into_inner()
                .into_iter()
                .map(|i| (i.as_ref().element_identifier.clone().into(), i))
                .collect::<BTreeMap<_, _>>()
                .try_into()
                // Can unwrap as there is always at least one element in a NonEmptyVec.
                .unwrap()
        }

        let Mdoc {
            mso,
            namespaces,
            issuer_auth,
            ..
        } = mdoc;
        let namespaces = namespaces
            .into_inner()
            .into_iter()
            .map(|(ns, v)| (ns.into(), extract(v)))
            .collect::<BTreeMap<_, _>>()
            .try_into()
            // Can unwrap as there is always at least one element in a NonEmptyMap.
            .unwrap();

        Document {
            id: Uuid::now_v1(&[0, 0, 0, 0, 0, 0]),
            mso,
            namespaces,
            issuer_auth,
        }
    }
}

/// Filter permitted items to only permit the items that were requested.
fn filter_permitted(request: &RequestedItems, permitted: PermittedItems) -> PermittedItems {
    permitted
        .into_iter()
        .filter_map(|(doc_type, namespaces)| {
            request
                .iter()
                .find(|item| {
                    let doc_type: String = doc_type.clone().into();
                    item.doc_type == doc_type
                })
                .map(|item| {
                    namespaces
                        .into_iter()
                        .filter_map(|(ns, elems)| {
                            let ns2: String = ns.clone().into();
                            item.namespaces
                                .get(&ns2)
                                .map(|req_elems| {
                                    elems
                                        .into_iter()
                                        .filter(|elem| {
                                            let elem2: String = elem.clone().into();
                                            req_elems.contains_key(&elem2)
                                        })
                                        .collect()
                                })
                                .map(|e| (ns, e))
                        })
                        .collect()
                })
                .map(|ns| (doc_type, ns))
        })
        .collect()
}

pub fn nearest_age_attestation(
    element_identifier: String,
    issuer_items: NonEmptyMap<String, Tag24<IssuerSignedItem>>,
) -> Result<Option<Tag24<IssuerSignedItem>>, Error> {
    let requested_age: u8 = parse_age_from_element_identifier(element_identifier)?;

    //find closest age_over_nn field that is true
    let owned_age_over_claims: Vec<(String, Tag24<IssuerSignedItem>)> = issuer_items
        .into_inner()
        .into_iter()
        .filter(|element| element.0.contains("age_over"))
        .collect();

    let age_over_claims_numerical: Result<Vec<(u8, Tag24<IssuerSignedItem>)>, Error> =
        owned_age_over_claims
            .iter()
            .map(|f| {
                Ok((
                    parse_age_from_element_identifier(f.to_owned().0)?,
                    f.to_owned().1,
                ))
            })
            .collect();

    let (true_age_over_claims, false_age_over_claims): (Vec<_>, Vec<_>) =
        age_over_claims_numerical?
            .into_iter()
            .partition(|x| x.1.to_owned().into_inner().element_value == CborValue::Bool(true));

    let nearest_age_over = true_age_over_claims
        .iter()
        .filter(|f| f.0 >= requested_age)
        .min_by_key(|claim| claim.0);

    if let Some(age_attestation) = nearest_age_over {
        return Ok(Some(age_attestation.1.to_owned()));
        // if there is no appropriate true age attestation, find the closest false age attestation
    } else {
        let nearest_age_under = false_age_over_claims
            .iter()
            .filter(|f| f.0 <= requested_age)
            .max_by_key(|claim| claim.0);

        if let Some(age_attestation) = nearest_age_under {
            return Ok(Some(age_attestation.1.to_owned()));
        }
    }

    //if there is still no appropriate attestation, do not return a value
    Ok(None)
}

/// Will parse the corresponding age as a number from the `age_over_*` element identifier.
///
/// # Example
///
/// ```
/// use isomdl::presentation::device::parse_age_from_element_identifier;
///
/// let element = "age_over_21".to_string();
/// let age = parse_age_from_element_identifier(element).unwrap();
/// assert_eq!(age, 21);
/// ```
pub fn parse_age_from_element_identifier(element_identifier: String) -> Result<u8, Error> {
    Ok(AgeOver::try_from(element_identifier)?.0)
}

/// Holds the age part from the `age_over_*` element identifier.
pub struct AgeOver(u8);

impl TryFrom<String> for AgeOver {
    type Error = Error;
    fn try_from(element_identifier: String) -> Result<Self, Self::Error> {
        if let Some(x) = element_identifier.strip_prefix("age_over_") {
            let age_over = AgeOver(str::parse::<u8>(x)?);
            Ok(age_over)
        } else {
            Err(Error::PrefixError)
        }
    }
}

#[cfg(test)]
mod test {
    use coset::{iana, CborSerializable, CoseSign1Builder};
    use ecdsa::Signature;
    use hex::FromHex;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::{NistP256, SecretKey};
    use serde_json::json;
    use signature::{Signer, Verifier};

    use crate::definitions::helpers::ByteStr;
    use crate::definitions::mso::DigestId;

    use super::*;

    #[test]
    fn filter_permitted() {
        let requested = serde_json::from_value(json!([
            {
                "docType": "doc_type_1",
                "nameSpaces": {
                    "namespace_1": {
                        "element_1": false,
                        "element_2": false,
                    },
                    "namespace_2": {
                        "element_1": false,
                    }
                }
            },
            {
                "docType": "doc_type_2",
                "nameSpaces": {
                    "namespace_1": {
                        "element_1": false,
                    }
                }
            }
        ]))
        .unwrap();
        let permitted = serde_json::from_value(json!({
            "doc_type_1": {
                "namespace_1": [
                    "element_1",
                    "element_3"
                ],
                "namespace_3": [
                    "element_1",
                ]
            },
            "doc_type_3": {
                "namespace_1": [
                    "element_1",
                ],
            }
        }))
        .unwrap();
        let expected: PermittedItems = serde_json::from_value(json!({
            "doc_type_1": {
                "namespace_1": [
                    "element_1",
                ],
            }
        }))
        .unwrap();

        let filtered = super::filter_permitted(&requested, permitted);

        assert_eq!(expected, filtered);
    }

    #[test]
    fn test_parse_age_from_element_identifier() {
        let element_identifier = "age_over_88".to_string();
        let age = parse_age_from_element_identifier(element_identifier).unwrap();
        assert_eq!(age, 88)
    }

    #[test]
    fn test_age_attestation_response() {
        let requested_element_identifier = "age_over_23".to_string();
        let element_identifier1 = "age_over_18".to_string();
        let element_identifier2 = "age_over_22".to_string();
        let element_identifier3 = "age_over_21".to_string();

        let random = vec![1, 2, 3, 4, 5];
        let issuer_signed_item1 = IssuerSignedItem {
            digest_id: DigestId::new(1),
            random: ByteStr::from(random.clone()),
            element_identifier: element_identifier1.clone(),
            element_value: CborValue::Bool(true),
        };

        let issuer_signed_item2 = IssuerSignedItem {
            digest_id: DigestId::new(2),
            random: ByteStr::from(random.clone()),
            element_identifier: element_identifier2.clone(),
            element_value: CborValue::Bool(false),
        };

        let issuer_signed_item3 = IssuerSignedItem {
            digest_id: DigestId::new(3),
            random: ByteStr::from(random),
            element_identifier: element_identifier3.clone(),
            element_value: CborValue::Bool(false),
        };

        let issuer_item1 = Tag24::new(issuer_signed_item1).unwrap();
        let issuer_item2 = Tag24::new(issuer_signed_item2).unwrap();
        let issuer_item3 = Tag24::new(issuer_signed_item3).unwrap();
        let mut issuer_items = NonEmptyMap::new(element_identifier1, issuer_item1.clone());
        issuer_items.insert(element_identifier2, issuer_item2.clone());
        issuer_items.insert(element_identifier3, issuer_item3.clone());

        let result = nearest_age_attestation(requested_element_identifier, issuer_items)
            .expect("failed to process age attestation request");

        assert_eq!(result.unwrap().inner_bytes, issuer_item2.inner_bytes);
    }

    #[test]
    fn test_str_to_u8() {
        let wib = "8";
        let x = wib.as_bytes();

        println!("{:?}", x);
    }

    // static COSE_SIGN1: &str = include_str!("../../test/definitions/cose/sign1/serialized.cbor");
    static COSE_KEY: &str = include_str!("../../test/definitions/cose/sign1/secret_key");

    fn sign(payload: &[u8]) -> Vec<u8> {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();

        let sig: Signature<NistP256> = signer.try_sign(payload).unwrap();
        sig.to_vec()
    }

    fn verify(sig: &[u8], payload: &[u8]) -> coset::Result<(), String> {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();
        let verifier: VerifyingKey = (&signer).into();
        let signature: Signature<NistP256> =
            Signature::from_slice(sig).map_err(|err| err.to_string())?;
        verifier
            .verify(payload, &signature)
            .map_err(|err| err.to_string())
    }

    #[test]
    fn test_coset() {
        // Inputs.
        let pt = b"This is the content";
        let aad = b"this is additional data";

        // Build a `CoseSign1` object.
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(b"11".to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(pt.to_vec())
            .create_signature(aad, sign) // closure to do sign operation
            .build();

        // Serialize to bytes.
        let sign1_data = sign1.to_vec().unwrap();
        println!(
            "'{}' + '{}' => {}",
            String::from_utf8_lossy(pt),
            String::from_utf8_lossy(aad),
            hex::encode(&sign1_data)
        );

        // At the receiving end, deserialize the bytes back to a `CoseSign1` object.
        let mut sign1 = coset::CoseSign1::from_slice(&sign1_data).unwrap();

        // At this point, real code would validate the protected headers.

        // Check the signature, which needs to have the same `aad` provided, by
        // providing a closure that can do the verify operation.
        let result = sign1.verify_signature(aad, verify);
        println!("Signature verified: {:?}.", result);
        assert!(result.is_ok());

        // Changing an unprotected header leaves the signature valid.
        sign1.unprotected.content_type = Some(coset::ContentType::Text("text/plain".to_owned()));
        assert!(sign1.verify_signature(aad, verify).is_ok());

        // Providing a different `aad` means the signature won't validate.
        assert!(sign1.verify_signature(b"not aad", verify).is_err());

        // Changing a protected header invalidates the signature.
        sign1.protected.original_data = None;
        sign1.protected.header.content_type =
            Some(coset::ContentType::Text("text/plain".to_owned()));
        assert!(sign1.verify_signature(aad, verify).is_err());
    }
}
