use crate::cbor;
use crate::cose::mac0::VerificationResult as Mac0VerificationResult;
use crate::cose::sign1::VerificationResult;
use crate::definitions::device_response::Document;
use crate::definitions::issuer_signed;
use crate::definitions::session::{derive_e_mac_key, get_shared_secret, SessionTranscript};
use crate::definitions::x509::{SupportedCurve, X5Chain};
use crate::definitions::DeviceAuth;
use crate::definitions::Mso;
use crate::definitions::{device_signed::DeviceAuthentication, helpers::Tag24};
use crate::presentation::reader::Error;
use anyhow::Result;
use digest::Mac;
use elliptic_curve::generic_array::GenericArray;
use hmac::Hmac;
use issuer_signed::IssuerSigned;
use p256::{FieldBytes, NistP256};
use p384::NistP384;
use sha2::Sha256;
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

pub fn device_authentication<S>(
    document: &Document,
    session_transcript: S,
    e_reader_key_private: &[u8; 32],
) -> Result<(), Error>
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
    // Clone for MAC ECDH before consuming via JWK conversion
    let s_device_key = device_key.clone();
    let jwk = SsiJwk::try_from(device_key)?;

    let namespaces_bytes = &document.device_signed.namespaces;
    let device_auth: &DeviceAuth = &document.device_signed.device_auth;

    let detached_payload = Tag24::new(DeviceAuthentication::new(
        session_transcript.clone(),
        document.doc_type.clone(),
        namespaces_bytes.clone(),
    ))
    .map_err(|_| Error::CborDecodingError)?;
    let cbor_payload = cbor::to_vec(&detached_payload)?;

    match device_auth {
        DeviceAuth::DeviceSignature(device_signature) => match jwk.params {
            Params::EC(ref p) => {
                let x_coordinate = p.x_coordinate.clone();
                let y_coordinate = p.y_coordinate.clone();
                let (Some(x), Some(y)) = (x_coordinate, y_coordinate) else {
                    return Err(Error::MdocAuth(
                        "device key jwk is missing coordinates".to_string(),
                    ));
                };

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
                            ecdsa::VerifyingKey::<NistP256>::from_encoded_point(&encoded_point)?;
                        device_signature
                            .verify::<ecdsa::VerifyingKey<NistP256>, p256::ecdsa::Signature>(
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
                            ecdsa::VerifyingKey::<NistP384>::from_encoded_point(&encoded_point)?;
                        device_signature
                            .verify::<ecdsa::VerifyingKey<NistP384>, p384::ecdsa::Signature>(
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
        },
        DeviceAuth::DeviceMac(device_mac) => {
            let priv_key_bytes = e_reader_key_private;
            // Per ISO 18013-5 §9.1.3.5, EMacKey uses ECDH with the mdoc authentication key
            // (SDeviceKey, the static key from the MSO) — not the ephemeral session key.
            let private_key =
                p256::SecretKey::from_bytes(FieldBytes::from_slice(priv_key_bytes))
                    .map_err(|e| Error::MdocAuth(format!("invalid reader private key: {e}")))?;
            let shared_secret = get_shared_secret(s_device_key, &private_key.into())
                .map_err(|e| Error::MdocAuth(format!("ECDH with SDeviceKey failed: {e}")))?;
            let session_transcript_bytes =
                Tag24::new(session_transcript.clone()).map_err(|_| Error::CborDecodingError)?;
            let e_mac_key = derive_e_mac_key(&shared_secret, &session_transcript_bytes)
                .map_err(|e| Error::MdocAuth(format!("failed to derive EMacKey: {e}")))?;
            let verifier = Hmac::<Sha256>::new_from_slice(e_mac_key.as_slice())
                .map_err(|e| Error::MdocAuth(format!("failed to create HMAC verifier: {e}")))?;

            let result = device_mac.verify(&verifier, Some(&cbor_payload), None);

            match result {
                Mac0VerificationResult::Success => Ok(()),
                Mac0VerificationResult::Failure(e) => {
                    Err(Error::MdocAuth(format!("failed verifying device mac: {e}")))
                }
                Mac0VerificationResult::Error(e) => {
                    Err(Error::MdocAuth(format!("error verifying device mac: {e}")))
                }
            }
        }
    }
}
