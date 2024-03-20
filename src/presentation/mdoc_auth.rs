use crate::definitions::device_response::Document;
use crate::definitions::issuer_signed;
use crate::definitions::x509::X5Chain;
use crate::definitions::DeviceAuth;
use crate::definitions::Mso;
use crate::definitions::{
    device_signed::DeviceAuthentication, helpers::Tag24, SessionTranscript180135,
};
use crate::presentation::reader::Error;
use crate::presentation::reader::Error as ReaderError;
use anyhow::Result;
use elliptic_curve::generic_array::GenericArray;
use issuer_signed::IssuerSigned;
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use ssi_jwk::Params;
use ssi_jwk::JWK as SsiJwk;

pub fn issuer_authentication(x5chain: X5Chain, issuer_signed: &IssuerSigned) -> Result<(), Error> {
    let signer_key = x5chain.get_signer_key()?;
    let verification_result: cose_rs::sign1::VerificationResult =
        issuer_signed
            .issuer_auth
            .verify::<VerifyingKey, Signature>(&signer_key, None, None);
    if !verification_result.success() {
        Err(ReaderError::ParsingError)?
    } else {
        Ok(())
    }
}

pub fn device_authentication(
    document: &Document,
    session_transcript: SessionTranscript180135,
) -> Result<(), Error> {
    let mso_bytes = document
        .issuer_signed
        .issuer_auth
        .payload()
        .ok_or(Error::DetachedIssuerAuth)?;
    let mso: Tag24<Mso> = serde_cbor::from_slice(mso_bytes).map_err(|_| Error::MSOParsing)?;
    let device_key = mso.into_inner().device_key_info.device_key;
    let jwk = SsiJwk::try_from(device_key)?;
    match jwk.params {
        Params::EC(p) => {
            let x_coordinate = p.x_coordinate.clone();
            let y_coordinate = p.y_coordinate.clone();
            let (Some(x), Some(y)) = (x_coordinate, y_coordinate) else {
                return Err(ReaderError::MdocAuth(
                    "device key jwk is missing coordinates".to_string(),
                ));
            };
            let encoded_point = p256::EncodedPoint::from_affine_coordinates(
                GenericArray::from_slice(x.0.as_slice()),
                GenericArray::from_slice(y.0.as_slice()),
                false,
            );
            let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)?;
            let namespaces_bytes = &document.device_signed.namespaces;
            let device_auth: &DeviceAuth = &document.device_signed.device_auth;

            //TODO: fix for attended use case:
            match device_auth {
                DeviceAuth::Signature { device_signature } => {
                    let detached_payload = Tag24::new(DeviceAuthentication::new(
                        session_transcript,
                        document.doc_type.clone(),
                        namespaces_bytes.clone(),
                    ))
                    .map_err(|_| ReaderError::CborDecodingError)?;
                    let external_aad = None;
                    let cbor_payload = serde_cbor::to_vec(&detached_payload)?;
                    let result = device_signature.verify::<VerifyingKey, Signature>(
                        &verifying_key,
                        Some(cbor_payload),
                        external_aad,
                    );
                    if !result.success() {
                        Err(ReaderError::ParsingError)?
                    } else {
                        Ok(())
                    }
                }
                DeviceAuth::Mac { .. } => {
                    Err(ReaderError::Unsupported)
                    // send not yet supported error
                }
            }
        }
        _ => Err(Error::MdocAuth("Unsupported device_key type".to_string())),
    }
}
