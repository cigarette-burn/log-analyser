//! Module for parsing, filtering, and analyzing server log files.
//!
//! This module acts as the core of the library, exposing the central [`Analyser`] structure
//! along with specialized submodules for error handling, predicate filters, iterative execution,
//! and raw log line processing.

pub mod analyser;
pub mod analyze_error;
pub mod filters;
pub mod iter_result;
pub mod log_entry;
pub mod parse_errors;

pub use analyser::Analyser;
pub use analyze_error::AnalyserErrors;
