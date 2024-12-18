use der::Encode;
use ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::NistP256;
use x509_cert::Certificate;

use crate::definitions::x509::util::public_key;

/// Check that the issuer certificate signed the subject certificate.
pub fn issuer_signed_subject(subject: &Certificate, issuer: &Certificate) -> bool {
    // TODO: Support curves other than P-256.
    let issuer_public_key: VerifyingKey<NistP256> = match public_key(issuer) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!("failed to decode issuer public key: {e:?}");
            return false;
        }
    };

    let sig: Signature<NistP256> = match Signature::from_der(subject.signature.raw_bytes()) {
        Ok(sig) => sig,
        Err(e) => {
            tracing::error!("failed to parse subject signature: {e:?}");
            return false;
        }
    };

    let tbs = match subject.tbs_certificate.to_der() {
        Ok(tbs) => tbs,
        Err(e) => {
            tracing::error!("failed to parse subject tbs: {e:?}");
            return false;
        }
    };

    match issuer_public_key.verify(&tbs, &sig) {
        Ok(()) => true,
        Err(e) => {
            tracing::info!("subject certificate signature could not be validated: {e:?}");
            false
        }
    }
}

#[cfg(test)]
mod test {
    use crate::definitions::x509::x5chain::CertificateWithDer;

    use super::issuer_signed_subject;

    #[test]
    pub fn correct_signature() {
        let target = include_bytes!("../../../../test/presentation/isomdl_iaca_signer.pem");
        let issuer = include_bytes!("../../../../test/presentation/isomdl_iaca_root_cert.pem");
        assert!(issuer_signed_subject(
            &CertificateWithDer::from_pem(target).unwrap().inner,
            &CertificateWithDer::from_pem(issuer).unwrap().inner,
        ))
    }

    #[test]
    pub fn incorrect_signature() {
        let issuer = include_bytes!("../../../../test/presentation/isomdl_iaca_signer.pem");
        let target = include_bytes!("../../../../test/presentation/isomdl_iaca_root_cert.pem");
        assert!(!issuer_signed_subject(
            &CertificateWithDer::from_pem(target).unwrap().inner,
            &CertificateWithDer::from_pem(issuer).unwrap().inner,
        ))
    }
}
