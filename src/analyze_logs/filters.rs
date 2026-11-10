use crate::analyze_logs::log_entry::LogEntry;

/// A trait alias for log entry filters.
///
/// Any closure or function that takes a reference to a [`LogEntry`] and returns a `bool`
/// automatically implements this trait, provided it has a `'static` lifetime.
pub trait EntryFilter: Fn(&LogEntry) -> bool + 'static {}

/// Blanket implementation to ensure all matching closures automatically implement [`EntryFilter`].
impl<T> EntryFilter for T where T: Fn(&LogEntry) -> bool + 'static {}

/// Creates a filter that matches log entries with a specific HTTP status code.
///
/// # Arguments
/// * `status` - The HTTP status code to match (e.g., 200, 404).
pub fn filter_by_status_code(status: u16) -> impl EntryFilter {
    move |entry: &LogEntry| entry.status() == status
}

/// Creates a filter that matches log entries with a specific HTTP method.
///
/// The input method string is automatically converted to uppercase to ensure case-insensitive matching.
///
/// # Arguments
/// * `method` - The HTTP method to match (e.g., "GET", "POST").
pub fn filter_by_method(method: &str) -> impl EntryFilter {
    let method = method.to_uppercase();
    move |entry: &LogEntry| *entry.method() == method
}

/// Creates a filter that checks if the request URL path contains the specified substring pattern.
///
/// # Arguments
/// * `pattern` - The substring to search for within the request path (e.g., "/api/v1").
pub fn filter_by_path_pattern(pattern: &str) -> impl EntryFilter {
    let pattern = pattern.to_string();
    move |entry: &LogEntry| entry.path().contains(&pattern)
}

/// Creates a filter that checks if the client IP address contains the specified substring pattern.
///
/// This allows for matching exact IP addresses as well as partial subnets.
///
/// # Arguments
/// * `ip_pattern` - The IP address or partial string to match (e.g., "192.168.1.").
pub fn by_ip(ip_pattern: &str) -> impl EntryFilter {
    let pattern = ip_pattern.to_string();
    move |entry: &LogEntry| entry.ip().contains(&pattern)
}
