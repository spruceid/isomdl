use crate::cbor;
use crate::cose::sign1::VerificationResult;
use crate::definitions::device_response::Document;
use crate::definitions::issuer_signed;
use crate::definitions::session::SessionTranscript;
use crate::definitions::x509::{SupportedCurve, X5Chain};
use crate::definitions::DeviceAuth;
use crate::definitions::Mso;
use crate::definitions::{device_signed::DeviceAuthentication, helpers::Tag24};
use crate::presentation::reader::Error;
use anyhow::Result;
use elliptic_curve::generic_array::GenericArray;
use issuer_signed::IssuerSigned;
use ssi_jwk::Params;
use ssi_jwk::JWK as SsiJwk;

pub fn issuer_authentication(x5chain: X5Chain, issuer_signed: &IssuerSigned) -> Result<(), Error> {
    let curve = SupportedCurve::from_certificate(x5chain.end_entity_certificate())
        .ok_or_else(|| Error::IssuerPublicKey(anyhow::anyhow!("unsupported curve")))?;

    let verification_result =
        match curve {
            SupportedCurve::P256 => {
                let signer_key: ecdsa::VerifyingKey<p256::NistP256> = x5chain
                    .end_entity_public_key()
                    .map_err(Error::IssuerPublicKey)?;
                issuer_signed
                    .issuer_auth
                    .verify::<ecdsa::VerifyingKey<p256::NistP256>, p256::ecdsa::Signature>(
                        &signer_key,
                        None,
                        None,
                    )
            }
            SupportedCurve::P384 => {
                let signer_key: ecdsa::VerifyingKey<p384::NistP384> = x5chain
                    .end_entity_public_key()
                    .map_err(Error::IssuerPublicKey)?;
                issuer_signed
                    .issuer_auth
                    .verify::<ecdsa::VerifyingKey<p384::NistP384>, p384::ecdsa::Signature>(
                        &signer_key,
                        None,
                        None,
                    )
            }
        };

    verification_result
        .into_result()
        .map_err(Error::IssuerAuthentication)
}

pub fn device_authentication<S>(document: &Document, session_transcript: S) -> Result<(), Error>
where
    S: SessionTranscript + Clone,
{
    let mso_bytes = document
        .issuer_signed
        .issuer_auth
        .payload
        .as_ref()
        .ok_or(Error::DetachedIssuerAuth)?;
    let mso: Tag24<Mso> = cbor::from_slice(mso_bytes).map_err(|_| Error::MSOParsing)?;
    let device_key = mso.into_inner().device_key_info.device_key;
    let jwk = SsiJwk::try_from(device_key)?;

    match jwk.params {
        Params::EC(ref p) => {
            let x_coordinate = p.x_coordinate.clone();
            let y_coordinate = p.y_coordinate.clone();
            let (Some(x), Some(y)) = (x_coordinate, y_coordinate) else {
                return Err(Error::MdocAuth(
                    "device key jwk is missing coordinates".to_string(),
                ));
            };

            let namespaces_bytes = &document.device_signed.namespaces;
            let device_auth: &DeviceAuth = &document.device_signed.device_auth;

            let DeviceAuth::DeviceSignature(device_signature) = device_auth else {
                return Err(Error::Unsupported);
            };

            let detached_payload = Tag24::new(DeviceAuthentication::new(
                session_transcript,
                document.doc_type.clone(),
                namespaces_bytes.clone(),
            ))
            .map_err(|_| Error::CborDecodingError)?;
            let cbor_payload = cbor::to_vec(&detached_payload)?;

            // Determine curve from JWK and verify accordingly
            let curve_name = p.curve.as_ref().ok_or_else(|| {
                Error::MdocAuth("device key JWK missing 'crv' parameter".to_string())
            })?;

            let curve = SupportedCurve::from_jwk_crv(curve_name)
                .ok_or_else(|| Error::MdocAuth(format!("unsupported curve: {curve_name}")))?;

            let result = match curve {
                SupportedCurve::P256 => {
                    let encoded_point = p256::EncodedPoint::from_affine_coordinates(
                        GenericArray::from_slice(x.0.as_slice()),
                        GenericArray::from_slice(y.0.as_slice()),
                        false,
                    );
                    let verifying_key =
                        ecdsa::VerifyingKey::<p256::NistP256>::from_encoded_point(&encoded_point)?;
                    device_signature
                        .verify::<ecdsa::VerifyingKey<p256::NistP256>, p256::ecdsa::Signature>(
                            &verifying_key,
                            Some(&cbor_payload),
                            None,
                        )
                }
                SupportedCurve::P384 => {
                    let encoded_point = p384::EncodedPoint::from_affine_coordinates(
                        GenericArray::from_slice(x.0.as_slice()),
                        GenericArray::from_slice(y.0.as_slice()),
                        false,
                    );
                    let verifying_key =
                        ecdsa::VerifyingKey::<p384::NistP384>::from_encoded_point(&encoded_point)?;
                    device_signature
                        .verify::<ecdsa::VerifyingKey<p384::NistP384>, p384::ecdsa::Signature>(
                            &verifying_key,
                            Some(&cbor_payload),
                            None,
                        )
                }
            };

            match result {
                VerificationResult::Success => Ok(()),
                VerificationResult::Failure(e) => Err(Error::MdocAuth(format!(
                    "failed verifying device signature: {e}"
                ))),
                VerificationResult::Error(e) => Err(Error::MdocAuth(format!(
                    "error verifying device signature: {e}"
                ))),
            }
        }
        _ => Err(Error::MdocAuth("Unsupported device_key type".to_string())),
    }
}
