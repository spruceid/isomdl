use time::OffsetDateTime;
use x509_cert::Certificate;

pub fn check_validity_period(certificate: &Certificate) -> Vec<Error> {
    let current_time = OffsetDateTime::now_utc();
    let validity = certificate.tbs_certificate.validity;
    let mut errors: Vec<Error> = vec![];
    if validity.not_after.to_unix_duration().as_secs() < current_time.unix_timestamp() as u64 {
        errors.push(Error::Expired);
    };
    if validity.not_before.to_unix_duration().as_secs() > current_time.unix_timestamp() as u64 {
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
