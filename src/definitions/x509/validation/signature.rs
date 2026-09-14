use der::Encode;
use ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::NistP256;
use p384::NistP384;
use x509_cert::Certificate;

use crate::definitions::x509::util::{public_key, SupportedCurve};

/// Macro to verify a DER-encoded signature for a specific curve.
///
/// This avoids code duplication while sidestepping the complex generic bounds
/// required for ECDSA verification across multiple curves.
macro_rules! verify_sig {
    ($curve:ty, $signing_cert:expr, $signature_bytes:expr, $tbs:expr) => {{
        let signing_key: VerifyingKey<$curve> = match public_key($signing_cert) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::error!("failed to decode signing certificate public key: {e:?}");
                return false;
            }
        };

        let sig: Signature<$curve> = match Signature::from_der($signature_bytes) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!("failed to parse signature: {e:?}");
                return false;
            }
        };

        match signing_key.verify($tbs, &sig) {
            Ok(()) => true,
            Err(e) => {
                tracing::info!("signature verification failed: {e:?}");
                false
            }
        }
    }};
}

/// Check that the issuer certificate signed the subject certificate.
pub fn issuer_signed_subject(subject: &Certificate, issuer: &Certificate) -> bool {
    let tbs = match subject.tbs_certificate.to_der() {
        Ok(tbs) => tbs,
        Err(e) => {
            tracing::error!("failed to encode subject tbs: {e:?}");
            return false;
        }
    };

    verify_signature(issuer, subject.signature.raw_bytes(), &tbs)
}

/// Verify a DER-encoded signature against a signing certificate's public key.
///
/// This is the shared verification primitive used by both certificate chain
/// validation and CRL signature validation.
pub(crate) fn verify_signature(
    signing_cert: &Certificate,
    signature_bytes: &[u8],
    tbs: &[u8],
) -> bool {
    let Some(curve) = SupportedCurve::from_certificate(signing_cert) else {
        tracing::error!("unsupported or missing curve OID in signing certificate");
        return false;
    };

    match curve {
        SupportedCurve::P256 => verify_sig!(NistP256, signing_cert, signature_bytes, tbs),
        SupportedCurve::P384 => verify_sig!(NistP384, signing_cert, signature_bytes, tbs),
    }
}

#[cfg(test)]
mod test {
    use crate::definitions::x509::x5chain::CertificateWithDer;

    use super::issuer_signed_subject;

    #[test]
    pub fn correct_signature_p256() {
        let target = include_bytes!("../../../../test/presentation/isomdl_iaca_signer.pem");
        let issuer = include_bytes!("../../../../test/presentation/isomdl_iaca_root_cert.pem");
        assert!(issuer_signed_subject(
            &CertificateWithDer::from_pem(target).unwrap().inner,
            &CertificateWithDer::from_pem(issuer).unwrap().inner,
        ))
    }

    #[test]
    pub fn incorrect_signature_p256() {
        let issuer = include_bytes!("../../../../test/presentation/isomdl_iaca_signer.pem");
        let target = include_bytes!("../../../../test/presentation/isomdl_iaca_root_cert.pem");
        assert!(!issuer_signed_subject(
            &CertificateWithDer::from_pem(target).unwrap().inner,
            &CertificateWithDer::from_pem(issuer).unwrap().inner,
        ))
    }

    #[test]
    pub fn correct_signature_p384() {
        let target = include_bytes!("../../../../test/presentation/owf_multipaz_ds_p384.pem");
        let issuer = include_bytes!("../../../../test/presentation/owf_multipaz_iaca_p384.pem");
        assert!(issuer_signed_subject(
            &CertificateWithDer::from_pem(target).unwrap().inner,
            &CertificateWithDer::from_pem(issuer).unwrap().inner,
        ))
    }

    #[test]
    pub fn incorrect_signature_p384() {
        // Swap issuer and target to test incorrect signature
        let issuer = include_bytes!("../../../../test/presentation/owf_multipaz_ds_p384.pem");
        let target = include_bytes!("../../../../test/presentation/owf_multipaz_iaca_p384.pem");
        assert!(!issuer_signed_subject(
            &CertificateWithDer::from_pem(target).unwrap().inner,
            &CertificateWithDer::from_pem(issuer).unwrap().inner,
        ))
    }
}
