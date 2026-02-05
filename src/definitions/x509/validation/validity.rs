use time::OffsetDateTime;
use x509_cert::Certificate;

/// Check certificate validity period against a specific time.
pub fn check_validity_period_at(certificate: &Certificate, at: OffsetDateTime) -> Vec<Error> {
    let validity = certificate.tbs_certificate.validity;
    let mut errors: Vec<Error> = vec![];

    let not_after = OffsetDateTime::from(validity.not_after.to_system_time());
    let not_before = OffsetDateTime::from(validity.not_before.to_system_time());

    if not_after < at {
        errors.push(Error::Expired);
    }
    if not_before > at {
        errors.push(Error::NotYetValid);
    }

    errors
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum Error {
    #[error("expired")]
    Expired,
    #[error("not yet valid")]
    NotYetValid,
}
