use crate::analyze_logs::AnalyserErrors;
use crate::analyze_logs::filters::{
    EntryFilter, by_ip, filter_by_method, filter_by_path_pattern, filter_by_status_code,
};
use crate::analyze_logs::iter_result::LogIterator;
use crate::analyze_logs::log_entry::LogEntry;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Default)]
pub struct Analyser {
    max_lines: usize,
    with_filters: bool,
    filters: Vec<Box<dyn EntryFilter>>,
}

//implementation block for the build pattern
impl Analyser {
    pub fn lines(mut self, max_lines: usize) -> Self {
        self.max_lines = max_lines;
        self
    }

    pub fn max_lines(&self) -> usize {
        self.max_lines
    }

    pub fn filters(&self) -> &Vec<Box<dyn EntryFilter>> {
        &self.filters
    }

    pub fn with_filters(mut self, option: bool) -> Self {
        self.with_filters = option;
        self
    }

    pub fn add_filter<F>(mut self, filter: F) -> Self
    where
        F: EntryFilter + 'static,
    {
        self.filters.push(Box::new(filter));
        self
    }
}

// implementation block for the functional component
impl Analyser {
    fn read_file(&self, path: &str) -> Result<BufReader<File>, AnalyserErrors> {
        let file = File::open(path)?;
        Ok(BufReader::new(file))
    }

    fn check_state(&self) -> Result<(), AnalyserErrors> {
        if self.with_filters && self.filters.is_empty() {
            Err(AnalyserErrors::FilterError)
        } else {
            Ok(())
        }
    }

    pub fn analyze_logs(self, path: &str) -> Result<LogIterator, AnalyserErrors> {
        self.check_state()?;
        let reader = self.read_file(path)?;
        let log_iter = LogIterator::new(reader.lines(), self.max_lines, self.filters);
        Ok(log_iter)
    }

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

// default methods for searching
impl Analyser {
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

    pub fn filter_status(self, status: u16) -> Self {
        self.add_filter(filter_by_status_code(status))
    }

    pub fn filter_method(self, method: &str) -> Self {
        self.add_filter(filter_by_method(method))
    }

    pub fn filter_path(self, pattern: &str) -> Self {
        self.add_filter(filter_by_path_pattern(pattern))
    }

    pub fn filter_by_ip(self, ip: &str) -> Self {
        self.add_filter(by_ip(ip))
    }

    pub fn filter_errors(self) -> Self {
        self.add_filter(|entry: &LogEntry| entry.status() >= 400)
    }

    pub fn filter_success(self) -> Self {
        self.add_filter(|entry: &LogEntry| entry.status() < 400)
    }
}
