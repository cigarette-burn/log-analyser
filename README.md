# Nginx Log Analyser CLI

A high-performance command-line utility written in **Rust** for parsing, filtering, and analyzing Nginx server access logs.

## Features
- **Fast & Lazy:** Uses streaming lazy iterators to process large log files line-by-line efficiently.
- **Advanced Filtering:** Filter logs dynamically by IP, HTTP Method, Status Code, or Path pattern.
- **Analytics Summary:** Provides a strict, clean operational summary including error rates and a Top-3 active IP addresses table.
- **Beautiful Output:** ANSI-colored terminal highlights for methods, paths, and status ranges.

## Installation & Run
```bash
# Clone the repository
git clone <your-repo-link>
cd log_analyser

# Run the analyzer with sample log
cargo run -- --file access.log -n 100
```

## Running Tests
```bash
cargo test
```
