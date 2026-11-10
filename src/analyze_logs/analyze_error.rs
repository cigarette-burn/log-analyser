use std::error::Error;
use std::fmt::Display;
use std::io;

/// Errors that can occur during log analysis operations.
///
/// This enum covers validation failures regarding filters as well as
/// underlying input/output filesystem interactions.
#[derive(Debug)]
pub enum AnalyserErrors {
    /// Triggered when the analyzer requires at least one filter (`with_filters` is enabled)
    /// but the filter collection is empty.
    FilterError,

    /// Wraps any standard filesystem input/output error encountered while opening
    /// or reading the log file.
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
    /// Automatically converts standard input/output errors into [`AnalyserErrors::IOFileError`].
    fn from(value: io::Error) -> Self {
        AnalyserErrors::IOFileError(value)
    }
}

impl Error for AnalyserErrors {
    /// Provides access to the underlying low-level cause for filesystem errors.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IOFileError(err) => Some(err),
            _ => None,
        }
    }
}
