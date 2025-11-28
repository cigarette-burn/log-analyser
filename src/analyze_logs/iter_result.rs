use crate::analyze_logs::{filters::EntryFilter, log_entry::LogEntry};
use std::{fs::File, io::BufReader};

pub struct LogIterator {
    lines: std::io::Lines<BufReader<File>>,
    max_lines: usize,
    filters: Vec<Box<dyn EntryFilter>>,
    current_position: usize,
}

impl LogIterator {
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
    type Item = LogEntry;

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_position < self.max_lines {
            let line = self.lines.next()?.ok()?;
            self.current_position += 1;

            if let Ok(entry) = LogEntry::parse(&line)
                && self.filters.iter().all(|f| f(&entry))
            {
                return Some(entry);
            }
        }
        None
    }
}
