use crate::analyze_logs::log_entry::LogEntry;

pub trait EntryFilter: Fn(&LogEntry) -> bool + 'static {}
impl<T> EntryFilter for T where T: Fn(&LogEntry) -> bool + 'static {}

pub fn filter_by_status_code(status: u16) -> impl EntryFilter {
    move |entry: &LogEntry| entry.status() == status
}

pub fn filter_by_method(method: &str) -> impl EntryFilter {
    let method = method.to_uppercase();
    move |entry: &LogEntry| *entry.method() == method
}

pub fn filter_by_path_pattern(pattern: &str) -> impl EntryFilter {
    let pattern = pattern.to_string();
    move |entry: &LogEntry| entry.path().contains(&pattern)
}

pub fn by_ip(ip_pattern: &str) -> impl EntryFilter {
    let pattern = ip_pattern.to_string();
    move |entry: &LogEntry| entry.ip().contains(&pattern)
}
