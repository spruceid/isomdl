use der::Encode;
use ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::NistP256;
use p384::NistP384;
use x509_cert::Certificate;

use crate::definitions::x509::util::{public_key, SupportedCurve};

/// Macro to verify a certificate signature for a specific curve.
///
/// This avoids code duplication while sidestepping the complex generic bounds
/// required for ECDSA verification across multiple curves.
macro_rules! verify_cert_signature {
    ($curve:ty, $subject:expr, $issuer:expr, $tbs:expr) => {{
        let issuer_public_key: VerifyingKey<$curve> = match public_key($issuer) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::error!("failed to decode issuer public key: {e:?}");
                return false;
            }
        };

        let sig: Signature<$curve> = match Signature::from_der($subject.signature.raw_bytes()) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!("failed to parse subject signature: {e:?}");
                return false;
            }
        };

        match issuer_public_key.verify($tbs, &sig) {
            Ok(()) => true,
            Err(e) => {
                tracing::info!("subject certificate signature could not be validated: {e:?}");
                false
            }
        }
    }};
}

/// Check that the issuer certificate signed the subject certificate.
pub fn issuer_signed_subject(subject: &Certificate, issuer: &Certificate) -> bool {
    let Some(curve) = SupportedCurve::from_certificate(issuer) else {
        tracing::error!("unsupported or missing curve OID in issuer certificate");
        return false;
    };

    let tbs = match subject.tbs_certificate.to_der() {
        Ok(tbs) => tbs,
        Err(e) => {
            tracing::error!("failed to encode subject tbs: {e:?}");
            return false;
        }
    };

    match curve {
        SupportedCurve::P256 => verify_cert_signature!(NistP256, subject, issuer, &tbs),
        SupportedCurve::P384 => verify_cert_signature!(NistP384, subject, issuer, &tbs),
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
