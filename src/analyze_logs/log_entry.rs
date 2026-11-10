use crate::analyze_logs::parse_errors::ParseError;

/// Represents a single parsed and validated Nginx log entry.
///
/// Contains structured fields extracted from a raw Combined Log Format line.
#[derive(Debug)]
pub struct LogEntry {
    log: String,
    ip: String,
    method: String,
    path: String,
    date: String,
    status: u16,
}

impl LogEntry {
    /// Returns a reference to the client's IP address.
    pub fn ip(&self) -> &String {
        &self.ip
    }

    /// Returns the HTTP status code of the response.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Returns a reference to the HTTP method used (e.g., "GET").
    pub fn method(&self) -> &String {
        &self.method
    }

    /// Returns a reference to the requested URL path.
    pub fn path(&self) -> &String {
        &self.path
    }

    /// Returns a reference to the original, raw log line string.
    pub fn log(&self) -> &String {
        &self.log
    }
}

impl LogEntry {
    /// Formats and prints the log entry to the standard output using ANSI colors.
    pub fn output(&self) {
        use colored::*;

        let status_colored = if self.status >= 500 {
            self.status.to_string().red().bold()
        } else if self.status >= 400 {
            self.status.to_string().yellow().bold()
        } else if self.status >= 300 {
            self.status.to_string().cyan()
        } else {
            self.status.to_string().green().bold()
        };

        let method_colored = match self.method.as_str() {
            "GET" => self.method.green(),
            "POST" => self.method.blue().bold(),
            "PUT" | "PATCH" => self.method.yellow(),
            "DELETE" => self.method.red().bold(),
            _ => self.method.normal(),
        };

        println!(
            "[{}] {} -> {} {} [{}]",
            self.date.white().dimmed(),
            self.ip.bright_cyan(),
            method_colored,
            self.path.bright_white(),
            status_colored
        );
    }

    /// Parses a raw Nginx log line into a structured [`LogEntry`].
    ///
    /// # Errors
    /// Returns [`ParseError`] if the format is corrupted, the IP is invalid,
    /// or the HTTP method is unsupported.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 10 {
            return Err(ParseError::InvalidFormat(format!(
                "Expected at least 12 parts, got {}: {}",
                parts.len(),
                line
            )));
        }

        let ip = parts[0];
        let date = format!(
            "{} {}",
            parts[3].trim_matches(&['[', ']'][..]),
            parts[4].trim_matches(']')
        );
        let method = parts[5].trim_matches('"');
        let path = format!("{} {}", parts[6], parts[7].trim_matches('"'));
        let status = parts[8];

        let validate_ip = Self::validate_ip(ip)?;
        let validate_status = Self::validate_status_code(status)?;
        let validate_method = Self::validate_method(method)?;

        Ok(Self {
            log: line.to_string(),
            ip: validate_ip,
            method: validate_method,
            path,
            date,
            status: validate_status,
        })
    }
}

impl LogEntry {
    /// Validates an IPv4 address string by checking its octets.
    fn validate_ip(ip: &str) -> Result<String, ParseError> {
        let ip_parts: Vec<&str> = ip.split(".").collect();
        if ip_parts.len() < 4 {
            return Err(ParseError::InvalidIP(format!(
                "IP parsing error: received {} parts | (expected 4 parts.)",
                ip_parts.len()
            )));
        }

        for part in ip_parts {
            let _: u8 = part
                .parse()
                .map_err(|_| ParseError::InvalidIP(format!("Invalid IP octet: {}", part)))?;
        }

        Ok(ip.to_string())
    }

    /// Validates and parses the HTTP status code.
    fn validate_status_code(status_code: &str) -> Result<u16, ParseError> {
        status_code.parse().map_err(|_| {
            ParseError::InvalidStatusCode(format!("Invalid status code: {}", status_code))
        })
    }

    /// Validates if the given HTTP method is standard and supported.
    fn validate_method(method: &str) -> Result<String, ParseError> {
        let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];

        if methods.contains(&method) {
            Ok(method.to_string())
        } else {
            Err(ParseError::InvalidMethod(format!(
                "Invalid HTTP method: {}",
                method
            )))
        }
    }
}
