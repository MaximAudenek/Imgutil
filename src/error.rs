use core::fmt;

#[derive(Debug)]
pub enum Error {
    Format,
    Verification,
    Capacity,
    Io(std::io::Error),
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Format => f.write_str("invalid input"),
            Error::Verification => f.write_str("verification failed"),
            Error::Capacity => f.write_str("input too large"),
            Error::Io(_) => f.write_str("I/O error"),
            Error::Internal => f.write_str("internal error"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
