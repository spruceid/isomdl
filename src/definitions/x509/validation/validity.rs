use time::OffsetDateTime;
use x509_cert::Certificate;

/// Check certificate validity period against a specific time.
pub fn check_validity_period_at(certificate: &Certificate, at: OffsetDateTime) -> Vec<Error> {
    let validity = certificate.tbs_certificate.validity;
    let mut errors: Vec<Error> = vec![];
    let at_unix = at.unix_timestamp() as u64;

    if validity.not_after.to_unix_duration().as_secs() < at_unix {
        errors.push(Error::Expired);
    };
    if validity.not_before.to_unix_duration().as_secs() > at_unix {
        errors.push(Error::NotYetValid);
    };

    errors
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum Error {
    #[error("expired")]
    Expired,
    #[error("not yet valid")]
    NotYetValid,
}
