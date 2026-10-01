use std::fmt;

/// A validation error tagged with the certificate it was found on.
///
/// The tag is a plain label rather than an enum because certificate profiles name their own
/// certificates: see [`CertificateProfile::end_entity_name`].
///
/// [`CertificateProfile::end_entity_name`]: super::CertificateProfile::end_entity_name
#[derive(Debug, Clone, Copy)]
pub struct ErrorWithContext<E> {
    context: &'static str,
    error: E,
}

impl<E: fmt::Display> ErrorWithContext<E> {
    pub fn labelled(context: &'static str, error: E) -> String {
        Self { context, error }.to_string()
    }

    pub fn comparison(error: E) -> String {
        Self::labelled("Comparison", error)
    }

    pub fn chain(error: E) -> String {
        Self::labelled("Certificate chain", error)
    }
}

impl<E: fmt::Display> fmt::Display for ErrorWithContext<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} error: {}", self.context, self.error)
    }
}
