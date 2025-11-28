use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum ParseError {
    InvalidFormat(String),
    InvalidStatusCode(String),
    InvalidMethod(String),
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
