use super::{
    mdoc_auth::device_authentication, mdoc_auth::issuer_authentication,
    trust_anchor::ValidationRuleSet,
};
use crate::definitions::device_key::cose_key::Error as CoseError;
use crate::definitions::Mso;
use crate::issuance::x5chain::X509;
use crate::presentation::reader::Error as ReaderError;
use crate::presentation::trust_anchor::TrustAnchorRegistry;
use crate::{
    definitions::{
        device_engagement::DeviceRetrievalMethod,
        device_request::{self, DeviceRequest, DocRequest, ItemsRequest},
        helpers::{non_empty_vec, NonEmptyVec, Tag24},
        session::{
            self, create_p256_ephemeral_keys, derive_session_key, get_shared_secret, Handover,
            SessionEstablishment,
        },
    },
    definitions::{DeviceEngagement, DeviceResponse, SessionData, SessionTranscript180135},
    issuance::X5Chain,
    presentation::trust_anchor::TrustAnchor,
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::hash::Hash;
use uuid::Uuid;

use x509_cert::{certificate::CertificateInner, der::Decode};

#[derive(Serialize, Deserialize)]
pub struct SessionManager {
    session_transcript: SessionTranscript180135,
    sk_device: [u8; 32],
    device_message_counter: u32,
    sk_reader: [u8; 32],
    reader_message_counter: u32,
    validation_ruleset: Option<ValidationRuleSet>,
    trust_anchor_registry: Option<TrustAnchorRegistry>,
}

pub struct ValidatedResponse {
    pub response: BTreeMap<String, Value>,
    pub issuer_authentication: Status,
    pub device_authentication: Status,
    pub errors: ValidationErrors,
}

pub struct ValidationErrors(pub BTreeMap<String, Vec<Error>>);

#[derive(Serialize, Deserialize)]
pub enum Status {
    Unchecked,
    Invalid,
    Valid,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the qr code had the wrong prefix or the contained data could not be decoded: {0}")]
    InvalidQrCode(anyhow::Error),
    #[error("Device did not transmit any data.")]
    DeviceTransmissionError,
    #[error("Device did not transmit an mDL.")]
    DocumentTypeError,
    #[error("the device did not transmit any mDL data.")]
    NoMdlDataTransmission,
    #[error("device did not transmit any data in the org.iso.18013.5.1 namespace.")]
    IncorrectNamespace,
    #[error("device responded with an error.")]
    HolderError,
    #[error("could not decrypt the response.")]
    DecryptionError,
    #[error("Unexpected CBOR type for offered value")]
    CborDecodingError,
    #[error("not a valid JSON input.")]
    JsonError,
    #[error("Unexpected date type for data_element.")]
    ParsingError,
    #[error("Request for data is invalid.")]
    InvalidRequest,
    #[error("Failed mdoc authentication: {0}")]
    MdocAuth(String),
    #[error("Currently unsupported format")]
    Unsupported,
}

impl From<serde_cbor::Error> for Error {
    fn from(_: serde_cbor::Error) -> Self {
        Error::CborDecodingError
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::JsonError
    }
}

impl From<x509_cert::der::Error> for Error {
    fn from(value: x509_cert::der::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<p256::ecdsa::Error> for Error {
    fn from(value: p256::ecdsa::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<x509_cert::spki::Error> for Error {
    fn from(value: x509_cert::spki::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<CoseError> for Error {
    fn from(value: CoseError) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<non_empty_vec::Error> for Error {
    fn from(value: non_empty_vec::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<asn1_rs::Error> for Error {
    fn from(value: asn1_rs::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl SessionManager {
    pub fn establish_session(
        qr_code: String,
        namespaces: device_request::Namespaces,
        trust_anchor_registry: Option<TrustAnchorRegistry>,
        validation_ruleset: Option<ValidationRuleSet>,
    ) -> Result<(Self, Vec<u8>, [u8; 16])> {
        let device_engagement_bytes =
            Tag24::<DeviceEngagement>::from_qr_code_uri(&qr_code).map_err(Error::InvalidQrCode)?;

        //generate own keys
        let key_pair = create_p256_ephemeral_keys()?;
        let e_reader_key_private = key_pair.0;
        let e_reader_key_public = Tag24::new(key_pair.1)?;

        //decode device_engagement
        let device_engagement = device_engagement_bytes.as_ref();
        let e_device_key = &device_engagement.security.1;

        // calculate ble Ident value
        let ble_ident = super::calculate_ble_ident(e_device_key)?;

        // derive shared secret
        let shared_secret = get_shared_secret(
            e_device_key.clone().into_inner(),
            &e_reader_key_private.into(),
        )?;

        let session_transcript = SessionTranscript180135(
            device_engagement_bytes,
            e_reader_key_public.clone(),
            Handover::QR,
        );

        let session_transcript_bytes = Tag24::new(session_transcript.clone())?;

        //derive session keys
        let sk_reader = derive_session_key(&shared_secret, &session_transcript_bytes, true)?.into();
        let sk_device =
            derive_session_key(&shared_secret, &session_transcript_bytes, false)?.into();

        let mut session_manager = Self {
            session_transcript,
            sk_device,
            device_message_counter: 0,
            sk_reader,
            reader_message_counter: 0,
            validation_ruleset,
            trust_anchor_registry,
        };

        let request = session_manager.build_request(namespaces)?;
        let session = SessionEstablishment {
            data: request.into(),
            e_reader_key: e_reader_key_public,
        };
        let session_request = serde_cbor::to_vec(&session)?;

        Ok((session_manager, session_request, ble_ident))
    }

    pub fn first_central_client_uuid(&self) -> Option<&Uuid> {
        self.session_transcript
            .0
            .as_ref()
            .device_retrieval_methods
            .as_ref()
            .and_then(|ms| {
                ms.as_ref()
                    .iter()
                    .filter_map(|m| match m {
                        DeviceRetrievalMethod::BLE(opt) => {
                            opt.central_client_mode.as_ref().map(|cc| &cc.uuid)
                        }
                        _ => None,
                    })
                    .next()
            })
    }

    pub fn new_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        let request = self.build_request(namespaces)?;
        let session = SessionData {
            data: Some(request.into()),
            status: None,
        };
        serde_cbor::to_vec(&session).map_err(Into::into)
    }

    fn build_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        // if !validate_request(namespaces.clone()).is_ok() {
        //     return Err(anyhow::Error::msg(
        //         "At least one of the namespaces contain an invalid combination of fields to request",
        //     ));
        // }
        let items_request = ItemsRequest {
            doc_type: "org.iso.18013.5.1.mDL".into(),
            namespaces,
            request_info: None,
        };
        let doc_request = DocRequest {
            reader_auth: None,
            items_request: Tag24::new(items_request)?,
        };
        let device_request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(doc_request),
        };
        let device_request_bytes = serde_cbor::to_vec(&device_request)?;
        session::encrypt_reader_data(
            &self.sk_reader.into(),
            &device_request_bytes,
            &mut self.reader_message_counter,
        )
        .map_err(|e| anyhow!("unable to encrypt request: {}", e))
    }

    pub fn handle_response(
        &mut self,
        response: &[u8],
        session_transcript: SessionTranscript180135,
    ) -> Result<ValidatedResponse, Error> {
        let session_data: SessionData = serde_cbor::from_slice(response)?;
        let encrypted_response = match session_data.data {
            None => return Err(Error::HolderError),
            Some(r) => r,
        };
        let decrypted_response = session::decrypt_device_data(
            &self.sk_device.into(),
            encrypted_response.as_ref(),
            &mut self.device_message_counter,
        )
        .map_err(|_e| Error::DecryptionError)?;
        let mut core_namespace = BTreeMap::<String, serde_json::Value>::new();
        let mut aamva_namespace = BTreeMap::<String, serde_json::Value>::new();

        let device_response: DeviceResponse = serde_cbor::from_slice(&decrypted_response)?;

        let document = device_response
            .documents
            .clone()
            .ok_or(ReaderError::DeviceTransmissionError)?
            .into_inner()
            .into_iter()
            .find(|doc| doc.doc_type == "org.iso.18013.5.1.mDL")
            .ok_or(ReaderError::DocumentTypeError)?;

        let issuer_signed = document.issuer_signed.clone();

        let mso_bytes = issuer_signed
            .issuer_auth
            .payload()
            .expect("expected a COSE_Sign1 with attached payload, found detached payload");
        let mso: Tag24<Mso> =
            serde_cbor::from_slice(mso_bytes).expect("unable to parse payload as Mso");

        let header = issuer_signed.issuer_auth.unprotected();
        let Some(x5chain) = header.get_i(33) else {
            return Err(ReaderError::MdocAuth("Missing x5chain header".to_string()));
        };

        let mut parsed_response = BTreeMap::<String, serde_json::Value>::new();
        let mut namespaces = device_response
            .documents
            .ok_or(Error::DeviceTransmissionError)?
            .into_inner()
            .into_iter()
            .find(|doc| doc.doc_type == "org.iso.18013.5.1.mDL")
            .ok_or(Error::DocumentTypeError)?
            .issuer_signed
            .namespaces
            .ok_or(Error::NoMdlDataTransmission)?
            .into_inner();

        namespaces
            .remove("org.iso.18013.5.1")
            .ok_or(Error::IncorrectNamespace)?
            .into_inner()
            .into_iter()
            .map(|item| item.into_inner())
            .for_each(|item| {
                let value = parse_response(item.element_value.clone());
                if let Ok(val) = value {
                    core_namespace.insert(item.element_identifier, val);
                }
            });

        parsed_response.insert(
            "org.iso.18013.5.1".to_string(),
            serde_json::to_value(core_namespace)?,
        );

        if let Some(aamva_response) = namespaces.remove("org.iso.18013.5.1.aamva") {
            aamva_response
                .into_inner()
                .into_iter()
                .map(|item| item.into_inner())
                .for_each(|item| {
                    let value = parse_response(item.element_value.clone());
                    if let Ok(val) = value {
                        aamva_namespace.insert(item.element_identifier, val);
                    }
                });

            parsed_response.insert(
                "org.iso.18013.5.1.aamva".to_string(),
                serde_json::to_value(aamva_namespace)?,
            );
        }

        let mut validated_response = ValidatedResponse {
            response: parsed_response,
            issuer_authentication: Status::Unchecked,
            device_authentication: Status::Unchecked,
            errors: ValidationErrors(BTreeMap::new()),
        };

        let certificate_errors =
            validate_x5chain(x5chain.to_owned(), self.trust_anchor_registry.clone());

        match certificate_errors {
            Ok(r) => {
                validated_response
                    .errors
                    .0
                    .insert("certificate_errors".to_string(), r);
                let valid_issuer_authentication =
                    issuer_authentication(x5chain.clone(), issuer_signed);
                match valid_issuer_authentication {
                    Ok(_r) => {
                        validated_response.issuer_authentication = Status::Valid;
                    }
                    Err(e) => {
                        validated_response.issuer_authentication = Status::Invalid;
                        validated_response
                            .errors
                            .0
                            .insert("issuer_authentication_errors".to_string(), vec![e]);
                    }
                }
            }
            Err(_e) => validated_response.issuer_authentication = Status::Invalid,
        }

        let valid_device_authentication = device_authentication(mso, document, session_transcript);
        match valid_device_authentication {
            Ok(_r) => {
                validated_response.device_authentication = Status::Valid;
            }
            Err(e) => {
                validated_response.device_authentication = Status::Invalid;
                validated_response
                    .errors
                    .0
                    .insert("device_authentication_errors".to_string(), vec![e]);
            }
        }

        Ok(validated_response)
    }
}

pub fn find_anchor(
    leaf_certificate: CertificateInner,
    trust_anchor_registry: Option<TrustAnchorRegistry>,
) -> Result<Option<TrustAnchor>, Error> {
    let leaf_issuer = leaf_certificate.tbs_certificate.issuer;

    let Some(root_certificates) = trust_anchor_registry else {
        return Ok(None);
    };
    let Some(trust_anchor) = root_certificates
        .certificates
        .into_iter()
        .find(|trust_anchor| match trust_anchor {
            TrustAnchor::Iaca(certificate) => {
                match x509_cert::Certificate::from_der(&certificate.bytes) {
                    Ok(root_cert) => root_cert.tbs_certificate.subject == leaf_issuer,
                    Err(_) => false,
                }
            }
            TrustAnchor::Custom(certificate, _ruleset) => {
                match x509_cert::Certificate::from_der(&certificate.bytes) {
                    Ok(root_cert) => root_cert.tbs_certificate.subject == leaf_issuer,
                    Err(_) => false,
                }
            }
            TrustAnchor::Aamva(certificate) => {
                match x509_cert::Certificate::from_der(&certificate.bytes) {
                    Ok(root_cert) => root_cert.tbs_certificate.subject == leaf_issuer,
                    Err(_) => false,
                }
            }
        })
    else {
        return Err(Error::MdocAuth(
            "The certificate issuer does not match any known trusted issuer".to_string(),
        ));
    };
    Ok(Some(trust_anchor))
}

// In 18013-5 the TrustAnchorRegistry is also referred to as the Verified Issuer Certificate Authority List (VICAL)
pub fn validate_x5chain(
    x5chain: CborValue,
    trust_anchor_registry: Option<TrustAnchorRegistry>,
) -> Result<Vec<Error>, Error> {
    match x5chain {
        CborValue::Bytes(bytes) => {
            let chain: Vec<X509> = vec![X509 {
                bytes: serde_cbor::from_slice(&bytes)?,
            }];
            let x5chain = X5Chain::from(NonEmptyVec::try_from(chain)?);
            x5chain.validate(trust_anchor_registry)
        }
        CborValue::Array(x509s) => {
            let mut chain = vec![];
            for x509 in x509s {
                match x509 {
                    CborValue::Bytes(bytes) => {
                        chain.push(X509{bytes: serde_cbor::from_slice(&bytes)?})

                    },
                    _ => return Err(Error::MdocAuth(format!("Expecting x509 certificate in the x5chain to be a cbor encoded bytestring, but received: {:?}", x509)))
                }
            }

            if !has_unique_elements(chain.clone()) {
                return Err(Error::MdocAuth(
                    "x5chain header contains at least one duplicate certificate".to_string(),
                ));
            }

            let x5chain = X5Chain::from(NonEmptyVec::try_from(chain)?);
            x5chain.validate(trust_anchor_registry)
        }
        _ => {
            Err(Error::MdocAuth(format!("Expecting x509 certificate in the x5chain to be a cbor encoded bytestring, but received: {:?}", x5chain)))
        }
    }
}

fn parse_response(value: CborValue) -> Result<Value, Error> {
    match value {
        CborValue::Text(s) => Ok(Value::String(s)),
        CborValue::Tag(_t, v) => {
            if let CborValue::Text(d) = *v {
                Ok(Value::String(d))
            } else {
                Err(Error::ParsingError)
            }
        }
        CborValue::Array(v) => {
            let mut array_response = Vec::<Value>::new();
            for a in v {
                let r = parse_response(a)?;
                array_response.push(r);
            }
            Ok(json!(array_response))
        }
        CborValue::Map(m) => {
            let mut map_response = serde_json::Map::<String, Value>::new();
            for (key, value) in m {
                if let CborValue::Text(k) = key {
                    let parsed = parse_response(value)?;
                    map_response.insert(k, parsed);
                }
            }
            let json = json!(map_response);
            Ok(json)
        }
        CborValue::Bytes(b) => Ok(json!(b)),
        CborValue::Bool(b) => Ok(json!(b)),
        CborValue::Integer(i) => Ok(json!(i)),
        _ => Err(Error::ParsingError),
    }
}

fn _validate_request(namespaces: device_request::Namespaces) -> Result<bool, Error> {
    // Check if request follows ISO18013-5 restrictions
    // A valid mdoc request can contain a maximum of 2 age_over_NN fields
    let age_over_nn_requested: Vec<(String, bool)> = namespaces
        .get("org.iso.18013.5.1")
        .map(|k| k.clone().into_inner())
        //To Do: get rid of unwrap
        .unwrap()
        .into_iter()
        .filter(|x| x.0.contains("age_over"))
        .collect();

    if age_over_nn_requested.len() > 2 {
        //To Do: Decide what should happen when more than two age_over_nn are requested
        return Err(Error::InvalidRequest);
    }

    Ok(true)
}
fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::presentation::reader::validate_x5chain;
    use crate::{
        issuance::x5chain::X509,
        presentation::trust_anchor::{TrustAnchor, TrustAnchorRegistry},
    };
    use anyhow::anyhow;

    static IACA_ROOT: &[u8] = include_bytes!("../../test/presentation/isomdl_iaca_root_cert.pem");
    //TODO fix this cert to contain issuer alternative name
    static IACA_INTERMEDIATE: &[u8] =
        include_bytes!("../../test/presentation/isomdl_iaca_intermediate.pem");
    // signed by the intermediate certificate
    //TODO fix this cert to contain issuer alternative name
    static IACA_LEAF_SIGNER: &[u8] =
        include_bytes!("../../test/presentation/isomdl_iaca_leaf_signer.pem");
    // signed directly by the root certificate
    static IACA_SIGNER: &[u8] = include_bytes!("../../test/presentation/isomdl_iaca_signer.pem");
    static INCORRECT_IACA_SIGNER: &[u8] =
        include_bytes!("../../test/presentation/isomdl_incorrect_iaca_signer.pem");

    #[test]
    fn nested_response_values() {
        let domestic_driving_privileges = serde_cbor::from_slice(&hex::decode("81A276646F6D65737469635F76656869636C655F636C617373A46A69737375655F64617465D903EC6A323032342D30322D31346B6578706972795F64617465D903EC6A323032382D30332D3131781B646F6D65737469635F76656869636C655F636C6173735F636F64656243207822646F6D65737469635F76656869636C655F636C6173735F6465736372697074696F6E76436C6173732043204E4F4E2D434F4D4D45524349414C781D646F6D65737469635F76656869636C655F7265737472696374696F6E7381A27821646F6D65737469635F76656869636C655F7265737472696374696F6E5F636F64656230317828646F6D65737469635F76656869636C655F7265737472696374696F6E5F6465736372697074696F6E78284D555354205745415220434F5252454354495645204C454E534553205748454E2044524956494E47").unwrap()).unwrap();
        let json = parse_response(domestic_driving_privileges).unwrap();
        let expected = serde_json::json!(
          [
            {
              "domestic_vehicle_class": {
                "issue_date": "2024-02-14",
                "expiry_date": "2028-03-11",
                "domestic_vehicle_class_code": "C ",
                "domestic_vehicle_class_description": "Class C NON-COMMERCIAL"
              },
              "domestic_vehicle_restrictions": [
                {
                  "domestic_vehicle_restriction_code": "01",
                  "domestic_vehicle_restriction_description": "MUST WEAR CORRECTIVE LENSES WHEN DRIVING"
                }
              ]
            }
          ]
        );
        assert_eq!(json, expected)
    }
    #[test]
    fn validate_x509_with_trust_anchor() {
        let root_bytes = pem_rfc7468::decode_vec(IACA_ROOT)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))
            .unwrap()
            .1;
        let trust_anchor = TrustAnchor::Iaca(X509 { bytes: root_bytes });
        let trust_anchor_registry = TrustAnchorRegistry {
            certificates: vec![trust_anchor],
        };
        let bytes = pem_rfc7468::decode_vec(IACA_SIGNER)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))
            .unwrap()
            .1;
        let x5chain: serde_cbor::Value =
            serde_cbor::Value::Bytes(serde_cbor::to_vec(&bytes).unwrap());

        let result = validate_x5chain(x5chain, Some(trust_anchor_registry));
        println!("result: {:?}", result)
    }

    #[test]
    fn validate_incorrect_x509_with_trust_anchor() {
        let root_bytes = pem_rfc7468::decode_vec(IACA_ROOT)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))
            .unwrap()
            .1;
        let trust_anchor = TrustAnchor::Iaca(X509 { bytes: root_bytes });
        let trust_anchor_registry = TrustAnchorRegistry {
            certificates: vec![trust_anchor],
        };
        let bytes = pem_rfc7468::decode_vec(INCORRECT_IACA_SIGNER)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))
            .unwrap()
            .1;
        let x5chain: serde_cbor::Value =
            serde_cbor::Value::Bytes(serde_cbor::to_vec(&bytes).unwrap());

        let result = validate_x5chain(x5chain, Some(trust_anchor_registry));
        println!("result: {:?}", result)
    }

    #[test]
    fn validate_x5chain_with_trust_anchor() {
        let root_bytes = pem_rfc7468::decode_vec(IACA_ROOT)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))
            .unwrap()
            .1;
        let trust_anchor = TrustAnchor::Iaca(X509 { bytes: root_bytes });
        let trust_anchor_registry = TrustAnchorRegistry {
            certificates: vec![trust_anchor],
        };

        let intermediate_bytes = pem_rfc7468::decode_vec(IACA_INTERMEDIATE)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))
            .unwrap()
            .1;

        let leaf_signer_bytes = pem_rfc7468::decode_vec(IACA_LEAF_SIGNER)
            .map_err(|e| anyhow!("unable to parse pem: {}", e))
            .unwrap()
            .1;

        let intermediate_b =
            serde_cbor::Value::Bytes(serde_cbor::to_vec(&intermediate_bytes).unwrap());
        let leaf_signer_b =
            serde_cbor::Value::Bytes(serde_cbor::to_vec(&leaf_signer_bytes).unwrap());

        let x5chain = serde_cbor::Value::Array(vec![leaf_signer_b, intermediate_b]);
        let result = validate_x5chain(x5chain, Some(trust_anchor_registry));
        println!("result: {:?}", result)
    }
}
