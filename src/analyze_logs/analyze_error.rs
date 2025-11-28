use std::error::Error;
use std::fmt::Display;
use std::io;

#[derive(Debug)]
pub enum AnalyserErrors {
    FilterError,
    IOFileError(io::Error),
}

impl Display for AnalyserErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FilterError => write!(f, "filters cannot be used. access denied."),
            Self::IOFileError(err) => write!(f, "file reading error: {}", err),
        }
    }
}

impl From<io::Error> for AnalyserErrors {
    fn from(value: io::Error) -> Self {
        AnalyserErrors::IOFileError(value)
    }
}

impl Error for AnalyserErrors {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IOFileError(err) => Some(err),
            _ => None,
        }
    }
}
