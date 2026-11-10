use std::error::Error;
use std::fmt::Display;

/// Errors that can occur during the parsing and validation of a raw Nginx log line.
///
/// These errors help pinpoint exact formatting issues within the log file fields,
/// such as corrupted HTTP status codes, malformed IPs, or unsupported HTTP methods.
#[derive(Debug)]
pub enum ParseError {
    /// Triggered when the log line does not contain the minimum expected number of whitespace-separated parts.
    InvalidFormat(String),

    /// Triggered when the HTTP status code field cannot be successfully converted into a valid 16-bit unsigned integer (`u16`).
    InvalidStatusCode(String),

    /// Triggered when the parsed HTTP method does not belong to the standard expected methods (e.g., GET, POST, PUT, DELETE).
    InvalidMethod(String),

    /// Triggered when the client IP field fails validation (e.g., missing octets or octet values outside the 0-255 range).
    InvalidIP(String),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidFormat(msg) => write!(f, "Invalid log format: {}", msg),
            ParseError::InvalidStatusCode(msg) => write!(f, "Invalid status code format: {}", msg),
            ParseError::InvalidMethod(msg) => write!(f, "Invalid method format: {}", msg),
            ParseError::InvalidIP(msg) => write!(f, "Invalid IP format: {}", msg),
        }
    }
}

impl Error for ParseError {}
