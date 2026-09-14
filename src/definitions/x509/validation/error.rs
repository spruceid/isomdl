use std::fmt;

#[derive(Debug, Clone, Copy)]
pub struct ErrorWithContext<E> {
    context: ErrorContext,
    error: E,
}

impl<E: fmt::Display> ErrorWithContext<E> {
    pub fn comparison(error: E) -> String {
        Self {
            context: ErrorContext::Comparison,
            error,
        }
        .to_string()
    }

    pub fn ds(error: E) -> String {
        Self {
            context: ErrorContext::DocumentSigner,
            error,
        }
        .to_string()
    }

    pub fn iaca(error: E) -> String {
        Self {
            context: ErrorContext::Iaca,
            error,
        }
        .to_string()
    }

    pub fn reader(error: E) -> String {
        Self {
            context: ErrorContext::Reader,
            error,
        }
        .to_string()
    }

    pub fn reader_ca(error: E) -> String {
        Self {
            context: ErrorContext::ReaderCa,
            error,
        }
        .to_string()
    }

    pub fn vical_signer(error: E) -> String {
        Self {
            context: ErrorContext::VicalSigner,
            error,
        }
        .to_string()
    }

    pub fn vical_authority(error: E) -> String {
        Self {
            context: ErrorContext::VicalAuthority,
            error,
        }
        .to_string()
    }

    pub fn chain(error: E) -> String {
        Self {
            context: ErrorContext::Chain,
            error,
        }
        .to_string()
    }
}

impl<E: fmt::Display> fmt::Display for ErrorWithContext<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} error: {}",
            match self.context {
                ErrorContext::Comparison => "Comparison",
                ErrorContext::DocumentSigner => "DS certificate",
                ErrorContext::Iaca => "IACA certificate",
                ErrorContext::Reader => "Reader certificate",
                ErrorContext::ReaderCa => "Reader CA certificate",
                ErrorContext::VicalSigner => "VICAL signer certificate",
                ErrorContext::VicalAuthority => "VICAL authority certificate",
                ErrorContext::Chain => "Certificate chain",
            },
            self.error,
        )
    }
}

#[derive(Debug, Clone, Copy)]
enum ErrorContext {
    Comparison,
    DocumentSigner,
    Iaca,
    Reader,
    ReaderCa,
    VicalSigner,
    VicalAuthority,
    Chain,
}
