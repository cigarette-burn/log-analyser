use crate::analyze_logs::parse_errors::ParseError;

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
    pub fn ip(&self) -> &String {
        &self.ip
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn method(&self) -> &String {
        &self.method
    }

    pub fn path(&self) -> &String {
        &self.path
    }

    pub fn log(&self) -> &String {
        &self.log
    }
}

impl LogEntry {
    pub fn output(&self) {
        println!("[-LOG ENTRY-]");
        println!("-> log: {}", self.log);
        println!("-> ip: {}", self.ip);
        println!("-> method: {}", self.method);
        println!("-> path: {}", self.path);
        println!("-> date: {}", self.date);
        println!("-> status: {}", self.status);
    }
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

    fn validate_status_code(status_code: &str) -> Result<u16, ParseError> {
        status_code.parse().map_err(|_| {
            ParseError::InvalidStatusCode(format!("Invalid status code: {}", status_code))
        })
    }

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
