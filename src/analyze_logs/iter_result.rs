use crate::analyze_logs::{filters::EntryFilter, log_entry::LogEntry};
use std::{fs::File, io::BufReader};

/// A lazy, streaming iterator over filtered log entries.
///
/// `LogIterator` reads a log file line by line, parsing and evaluating each line
/// against a set of active filters without loading the entire file into memory.
pub struct LogIterator {
    /// The underlying input line stream from the buffered file reader.
    lines: std::io::Lines<BufReader<File>>,
    /// The maximum number of total lines allowed to be processed before stopping.
    max_lines: usize,
    /// A list of active dynamic filters that every valid log entry must satisfy.
    filters: Vec<Box<dyn EntryFilter>>,
    /// The current total line counter tracked during iteration.
    current_position: usize,
}

impl LogIterator {
    /// Constructs a new `LogIterator` with the specified lines stream, line limit, and filters.
    ///
    /// # Arguments
    /// * `lines` - The raw line stream from a buffered file reader.
    /// * `max_lines` - The maximum line processing limit.
    /// * `filters` - A collection of boxed dynamic filters.
    pub fn new(
        lines: std::io::Lines<BufReader<File>>,
        max_lines: usize,
        filters: Vec<Box<dyn EntryFilter>>,
    ) -> Self {
        Self {
            lines,
            max_lines,
            filters,
            current_position: 0,
        }
    }
}

impl Iterator for LogIterator {
    /// The type of the elements being iterated over.
    type Item = LogEntry;

    /// Advances the iterator and returns the next parsed and filtered [`LogEntry`].
    ///
    /// It skips lines that do not match the combined filters or fail to parse,
    /// and returns `None` once the end of the file or the `max_lines` threshold is reached.
    fn next(&mut self) -> Option<Self::Item> {
        while self.current_position < self.max_lines {
            let line = self.lines.next()?.ok()?;
            self.current_position += 1;

            // Uses nightly-stable let_chains feature to safely parse and evaluate predicates in place
            if let Ok(entry) = LogEntry::parse(&line)
                && self.filters.iter().all(|f| f(&entry))
            {
                return Some(entry);
            }
        }
        None
    }
}
