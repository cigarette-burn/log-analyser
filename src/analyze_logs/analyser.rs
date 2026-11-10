use crate::analyze_logs::AnalyserErrors;
use crate::analyze_logs::filters::{
    EntryFilter, by_ip, filter_by_method, filter_by_path_pattern, filter_by_status_code,
};
use crate::analyze_logs::iter_result::LogIterator;
use crate::analyze_logs::log_entry::LogEntry;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// A log analyzer that configures filters and processes log files.
///
/// `Analyser` utilizes the **Builder Pattern** to dynamically chain filters
/// and set operational constraints (such as maximum lines to process) before execution.
#[derive(Default)]
pub struct Analyser {
    /// The maximum number of log lines to process.
    max_lines: usize,
    /// A flag indicating whether the analyzer requires at least one active filter.
    with_filters: bool,
    /// A collection of heap-allocated dynamic filters implementing the [`EntryFilter`] trait.
    filters: Vec<Box<dyn EntryFilter>>,
}

// Implementation block for the Builder Pattern
impl Analyser {
    /// Sets the maximum number of lines to read from the log file.
    ///
    /// # Arguments
    /// * `max_lines` - The line limit.
    pub fn lines(mut self, max_lines: usize) -> Self {
        self.max_lines = max_lines;
        self
    }

    /// Returns the maximum number of lines configured for this analyzer.
    pub fn max_lines(&self) -> usize {
        self.max_lines
    }

    /// Returns a reference to the vector of currently configured filters.
    pub fn filters(&self) -> &Vec<Box<dyn EntryFilter>> {
        &self.filters
    }

    /// Enforces or relaxes the requirement of having filters during analysis.
    ///
    /// If set to `true`, execution will fail if no filters are attached.
    pub fn with_filters(mut self, option: bool) -> Self {
        self.with_filters = option;
        self
    }

    /// Appends a custom filter to the analyzer.
    ///
    /// # Arguments
    /// * `filter` - A type implementing the [`EntryFilter`] trait.
    pub fn add_filter<F>(mut self, filter: F) -> Self
    where
        F: EntryFilter + 'static,
    {
        self.filters.push(Box::new(filter));
        self
    }
}

// Implementation block for the functional components
impl Analyser {
    /// Opens the specified file and wraps it in a [`BufReader`].
    ///
    /// # Errors
    /// Returns [`AnalyserErrors::IOFileError`] if the file cannot be opened.
    fn read_file(&self, path: &str) -> Result<BufReader<File>, AnalyserErrors> {
        let file = File::open(path)?;
        Ok(BufReader::new(file))
    }

    /// Validates the internal state of the analyzer before starting processing.
    ///
    /// # Errors
    /// Returns [`AnalyserErrors::FilterError`] if `with_filters` is true but no filters are set.
    fn check_state(&self) -> Result<(), AnalyserErrors> {
        if self.with_filters && self.filters.is_empty() {
            Err(AnalyserErrors::FilterError)
        } else {
            Ok(())
        }
    }

    /// Analyzes the log file and returns a streaming lazy iterator ([`LogIterator`]).
    ///
    /// # Arguments
    /// * `path` - The path to the target log file.
    ///
    /// # Errors
    /// Returns an error if the state validation fails or if the file cannot be opened.
    pub fn analyze_logs(self, path: &str) -> Result<LogIterator, AnalyserErrors> {
        self.check_state()?;
        let reader = self.read_file(path)?;
        let log_iter = LogIterator::new(reader.lines(), self.max_lines, self.filters);
        Ok(log_iter)
    }

    /// Analyzes the log file and eagerly collects all matching entries into a vector.
    ///
    /// # Arguments
    /// * `path` - The path to the target log file.
    ///
    /// # Errors
    /// Returns an error if the state validation fails or if the file cannot be opened.
    pub fn analyze(self, path: &str) -> Result<Vec<LogEntry>, AnalyserErrors> {
        self.check_state()?;
        let reader = self.read_file(path)?;
        let entries: Vec<LogEntry> = reader
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| LogEntry::parse(&line).ok())
            .filter(|le| {
                if self.filters.is_empty() {
                    true
                } else {
                    self.filters.iter().all(|f| f(le))
                }
            })
            .take(self.max_lines)
            .collect();

        Ok(entries)
    }

    /// Analyzes logs with an additional ad-hoc filter injected at execution time.
    ///
    /// # Arguments
    /// * `path` - The path to the target log file.
    /// * `f` - An additional one-off filter closure/function.
    pub fn custom_analyze_logs(
        self,
        path: &str,
        f: impl EntryFilter + 'static,
    ) -> Result<LogIterator, AnalyserErrors> {
        self.check_state()?;
        let reader = self.read_file(path)?;
        let mut filters = self.filters;
        filters.push(Box::new(f));
        Ok(LogIterator::new(reader.lines(), self.max_lines, filters))
    }
}

// Default convenience methods for quick filtering and searching
impl Analyser {
    /// Performs a plain text substring search across the entire raw log line.
    ///
    /// # Arguments
    /// * `path` - The path to the target log file.
    /// * `pattern` - The text snippet to search for.
    pub fn search_by_pattern(
        self,
        path: &str,
        pattern: &str,
    ) -> Result<LogIterator, AnalyserErrors> {
        let query = pattern.to_string();
        let reader = self.read_file(path)?;
        let f = move |le: &LogEntry| le.log().contains(&query);
        Ok(LogIterator::new(
            reader.lines(),
            self.max_lines,
            vec![Box::new(f)],
        ))
    }

    /// Shorthand method to add a specific HTTP status code filter.
    pub fn filter_status(self, status: u16) -> Self {
        self.add_filter(filter_by_status_code(status))
    }

    /// Shorthand method to add an HTTP method filter (e.g., "GET", "POST").
    pub fn filter_method(self, method: &str) -> Self {
        self.add_filter(filter_by_method(method))
    }

    /// Shorthand method to add a URL path pattern matching filter.
    pub fn filter_path(self, pattern: &str) -> Self {
        self.add_filter(filter_by_path_pattern(pattern))
    }

    /// Shorthand method to filter entries by a specific IP address or subnet pattern.
    pub fn filter_by_ip(self, ip: &str) -> Self {
        self.add_filter(by_ip(ip))
    }

    /// Shorthand method to filter and retain only error logs (HTTP status >= 400).
    pub fn filter_errors(self) -> Self {
        self.add_filter(|entry: &LogEntry| entry.status() >= 400)
    }

    /// Shorthand method to filter and retain only successful logs (HTTP status < 400).
    pub fn filter_success(self) -> Self {
        self.add_filter(|entry: &LogEntry| entry.status() < 400)
    }
}
