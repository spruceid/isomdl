use crate::cbor;
use crate::cose::mac0::VerificationResult as Mac0VerificationResult;
use crate::cose::sign1::VerificationResult;
use crate::definitions::device_response::Document;
use crate::definitions::issuer_signed;
use crate::definitions::issuer_signed::IssuerNamespaces;
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
        .map_err(Error::IssuerAuthentication)?;

    // The signature over the MSO is valid. Per ISO/IEC 18013-5 §9.1.2.5, issuer
    // data authentication also requires binding the disclosed data element values
    // to the digests committed to in the MSO: recompute the digest of every
    // returned `IssuerSignedItem` and check it against `ValueDigests`. Without this
    // a holder could alter element values while reusing the genuine issuer signature.
    if let Some(namespaces) = &issuer_signed.namespaces {
        let mso_bytes = issuer_signed
            .issuer_auth
            .payload
            .as_ref()
            .ok_or(Error::DetachedIssuerAuth)?;
        let mso = cbor::from_slice::<Tag24<Mso>>(mso_bytes)
            .map_err(|_| Error::MSOParsing)?
            .into_inner();
        verify_value_digests(&mso, namespaces)?;
    }

    Ok(())
}

/// Recompute the digest of every disclosed [`IssuerSignedItem`] and verify it
/// matches the corresponding entry in the MSO's `value_digests`.
///
/// Only the *disclosed* items are checked (each must have a matching digest);
/// the MSO legitimately carries digests for undisclosed items and decoys, so we
/// do not require the reverse mapping — that would break selective disclosure.
///
/// [`IssuerSignedItem`]: crate::definitions::issuer_signed::IssuerSignedItem
fn verify_value_digests(mso: &Mso, namespaces: &IssuerNamespaces) -> Result<(), Error> {
    for (namespace, items) in namespaces.iter() {
        let expected_digests = mso.value_digests.get(namespace).ok_or_else(|| {
            Error::IssuerDigestMismatch(format!(
                "MSO contains no value digests for namespace {namespace}"
            ))
        })?;

        for item in items.iter() {
            let digest_id = item.as_ref().digest_id;
            let expected = expected_digests.get(&digest_id).ok_or_else(|| {
                Error::IssuerDigestMismatch(format!(
                    "MSO has no digest for digestID {digest_id:?} in namespace {namespace}"
                ))
            })?;

            let item_bytes = cbor::to_vec(item)?;
            let computed = mso.digest_algorithm.digest(&item_bytes);

            if computed.as_slice() != expected.as_ref() {
                return Err(Error::IssuerDigestMismatch(format!(
                    "digest mismatch for element {:?} (digestID {digest_id:?}) in namespace {namespace}",
                    item.as_ref().element_identifier
                )));
            }
        }
    }

    Ok(())
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
            // MAC authentication is only defined for cipher suite 1 (ISO 18013-5 §9.1.3.5),
            // which uses P-256. Other curves are not supported for COSE_Mac0.
            // Per §9.1.3.5, EMacKey uses ECDH with the mdoc authentication key
            // (SDeviceKey, the static key from the MSO) — not the ephemeral session key.
            let private_key =
                p256::SecretKey::from_bytes(FieldBytes::from_slice(e_reader_key_private))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definitions::helpers::{NonEmptyMap, NonEmptyVec, Tag24};
    use crate::definitions::issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes};

    const ISO_NAMESPACE: &str = "org.iso.18013.5.1";

    static ISSUER_CERT: &[u8] = include_bytes!("../../../test/issuance/issuer-cert.pem");

    fn issuer_x5chain() -> X5Chain {
        X5Chain::builder()
            .with_pem_certificate(ISSUER_CERT)
            .unwrap()
            .build()
            .unwrap()
    }

    /// Rebuild `namespaces`, replacing the `element_value` of the item whose
    /// `element_identifier == name` with `new_value`. The MSO / `issuer_auth`
    /// signature is left completely untouched.
    fn tamper_element(
        namespaces: &IssuerNamespaces,
        name: &str,
        new_value: ciborium::Value,
    ) -> IssuerNamespaces {
        let mut ns_map = namespaces.clone().into_inner();
        let items = ns_map
            .get_mut(ISO_NAMESPACE)
            .expect("iso namespace present");

        let tampered: Vec<IssuerSignedItemBytes> = items
            .clone()
            .into_inner()
            .into_iter()
            .map(|item_bytes| {
                let mut item = item_bytes.as_ref().clone();
                if item.element_identifier == name {
                    item.element_value = new_value.clone();
                    Tag24::new(item).expect("re-encode tampered item")
                } else {
                    item_bytes
                }
            })
            .collect();

        *items = NonEmptyVec::maybe_new(tampered).expect("non-empty");
        NonEmptyMap::maybe_new(ns_map).expect("non-empty")
    }

    fn age_over_21(namespaces: &IssuerNamespaces) -> Option<bool> {
        namespaces
            .get(ISO_NAMESPACE)?
            .iter()
            .map(|i| i.as_ref())
            .find(|i| i.element_identifier == "age_over_21")
            .and_then(|i| i.element_value.as_bool())
    }

    /// A holder (or a MITM on an unencrypted channel) flips `age_over_21` from
    /// `true` to `false` while reusing the genuine issuer signature, and issuer
    /// authentication must reject it.
    ///
    /// Per ISO/IEC 18013-5 §9.1.2.5 the reader MUST recompute the digest of each
    /// returned `IssuerSignedItem` and compare it against `ValueDigests` in the MSO.
    /// This is a regression test for the fix that added that check: without it the
    /// tampering went undetected because the disclosed values were never bound to
    /// the MSO digests.
    #[test]
    fn tampered_data_element_rejected_by_issuer_authentication() {
        let mdoc = crate::issuance::mdoc::test::minimal_test_mdoc().expect("issue mdoc");
        let x5chain = issuer_x5chain();

        // Baseline: genuine, issuer-signed response verifies and says age_over_21 = true.
        let genuine = IssuerSigned {
            namespaces: Some(mdoc.namespaces.clone()),
            issuer_auth: mdoc.issuer_auth.clone(),
        };
        assert_eq!(
            age_over_21(genuine.namespaces.as_ref().unwrap()),
            Some(true)
        );
        issuer_authentication(x5chain.clone(), &genuine)
            .expect("genuine response should pass issuer authentication");

        // Attack: flip age_over_21 to false, reusing the ORIGINAL issuer signature.
        let tampered_namespaces = tamper_element(
            &mdoc.namespaces,
            "age_over_21",
            ciborium::Value::Bool(false),
        );
        assert_eq!(age_over_21(&tampered_namespaces), Some(false));

        let tampered = IssuerSigned {
            namespaces: Some(tampered_namespaces),
            issuer_auth: mdoc.issuer_auth.clone(),
        };

        // The digest of the tampered item no longer matches the MSO, so the
        // value-digest check must reject the forged claim.
        let result = issuer_authentication(x5chain, &tampered);
        assert!(
            matches!(result, Err(Error::IssuerDigestMismatch(_))),
            "issuer_authentication did not reject tampered data: {result:?}"
        );
    }

    /// Rebuild `issuer_auth` so the MSO's `value_digests` are recomputed to match
    /// `tampered_namespaces`. This is what a more sophisticated attacker would do to
    /// defeat the value-digest check — but rewriting the MSO changes the COSE_Sign1
    /// payload, and the attacker cannot re-sign it without the issuer's private key.
    fn forge_consistent_mso(
        genuine: &IssuerSigned,
        tampered_namespaces: IssuerNamespaces,
    ) -> IssuerSigned {
        let mso_bytes = genuine
            .issuer_auth
            .payload
            .as_ref()
            .expect("attached payload");
        let mut mso = cbor::from_slice::<Tag24<Mso>>(mso_bytes)
            .expect("parse mso")
            .into_inner();

        let alg = mso.digest_algorithm;
        for (namespace, items) in tampered_namespaces.iter() {
            let digests = mso
                .value_digests
                .get_mut(namespace)
                .expect("namespace present in mso");
            for item in items.iter() {
                let item_bytes = cbor::to_vec(item).expect("encode item");
                digests.insert(item.as_ref().digest_id, alg.digest(&item_bytes).into());
            }
        }

        let mut issuer_auth = genuine.issuer_auth.clone();
        issuer_auth.payload =
            Some(cbor::to_vec(&Tag24::new(mso).expect("wrap mso")).expect("encode mso"));

        IssuerSigned {
            namespaces: Some(tampered_namespaces),
            issuer_auth,
        }
    }

    /// The counterpart to [`tampered_data_element_rejected_by_issuer_authentication`]: even
    /// when the attacker also rewrites the MSO's `value_digests` so the forged element
    /// hashes correctly (defeating the digest check in isolation), the tampering is still
    /// caught — this time by the COSE_Sign1 signature over the MSO, which no longer
    /// verifies against the issuer's certificate.
    #[test]
    fn tampered_value_and_matching_mso_digest_fails_issuer_authentication() {
        let mdoc = crate::issuance::mdoc::test::minimal_test_mdoc().expect("issue mdoc");
        let x5chain = issuer_x5chain();

        let genuine = IssuerSigned {
            namespaces: Some(mdoc.namespaces.clone()),
            issuer_auth: mdoc.issuer_auth.clone(),
        };

        // Flip age_over_21 and forge a matching MSO digest for it.
        let tampered_namespaces = tamper_element(
            &mdoc.namespaces,
            "age_over_21",
            ciborium::Value::Bool(false),
        );
        assert_eq!(age_over_21(&tampered_namespaces), Some(false));

        let forged = forge_consistent_mso(&genuine, tampered_namespaces);

        // The forged MSO digests DO match the tampered items, so the value-digest check
        // would pass. Verification must therefore fail at the signature step instead.
        let result = issuer_authentication(x5chain, &forged);
        assert!(
            matches!(result, Err(Error::IssuerAuthentication(_))),
            "expected the MSO signature check to reject the forged MSO, got: {result:?}"
        );
    }
}
