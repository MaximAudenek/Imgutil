use core::fmt;

#[derive(Debug)]
pub enum Error {
    Format,
    Verification,
    Capacity,
    ReadIo(std::io::Error),
    WriteIo(std::io::Error),
    InvalidArgs,
    Internal,
}

impl Error {
    /// The exact user-facing string for this error per SPEC.md. Internal
    /// variants are deliberately collapsed: an attacker observing the message
    /// cannot distinguish wrong-password, corrupted-image, missing-chunk,
    /// tampered-image, or wrong-count.
    pub fn user_message(&self) -> &'static str {
        match self {
            Error::Format | Error::Verification => "Authentication failed.",
            Error::ReadIo(_) => "Could not read file.",
            Error::WriteIo(_) => "Could not write file.",
            Error::InvalidArgs => "Invalid arguments.",
            Error::Capacity | Error::Internal => "An error occurred.",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.user_message())
    }
}

impl std::error::Error for Error {}
