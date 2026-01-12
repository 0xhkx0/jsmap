# jsmap - JavaScript Bug Bounty Scanner

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Release: v0.0.1](https://img.shields.io/badge/Release-v0.0.1-brightgreen.svg)](https://github.com/0xhkx0/jsmap/releases/tag/v0.0.1)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org)

jsmap is a comprehensive bug bounty JavaScript scanner designed to identify API endpoints, URLs, secrets, and other sensitive information embedded in JavaScript files. Similar to sqlmap but for JavaScript analysis.

## Features

### Pattern Detection
- **API Endpoints**: Identifies REST API endpoints and routing patterns
- **URLs**: Extracts internal and external URLs
- **Secrets**: Detects API keys, tokens, MongoDB URIs, and JWT tokens
- **Sensitive Files**: Finds file references and potential admin paths
- **Email Addresses**: Extracts email addresses from code
- **Minified Code Detection**: Identifies and beautifies minified JavaScript

### Source Map Support
- Automatic source map detection and fetching
- JavaScript beautification using source maps
- Original source code extraction for better analysis

### Multiple Input Methods
- **Single URL**: Analyze a specific JavaScript file
- **Crawling**: Recursively crawl websites to find all JavaScript files
- **File Input**: Analyze local JavaScript files
- **URL Lists**: Process multiple URLs in batch
- **Raw Requests**: Parse Burp Suite raw requests or HTTP request format

### Flexible Output
- **Table**: Human-readable formatted output
- **JSON**: Structured data for automation
- **CSV**: Spreadsheet-compatible format
- **HTML**: Professional reports with styling

## Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/0xhkx0/jsmap/releases):

```bash
# Linux (amd64)
wget https://github.com/0xhkx0/jsmap/releases/download/v0.0.1/jsmap-linux-amd64
chmod +x jsmap-linux-amd64
./jsmap-linux-amd64 --help

# macOS (Intel)
wget https://github.com/0xhkx0/jsmap/releases/download/v0.0.1/jsmap-darwin-amd64
chmod +x jsmap-darwin-amd64
./jsmap-darwin-amd64 --help

# macOS (Apple Silicon)
wget https://github.com/0xhkx0/jsmap/releases/download/v0.0.1/jsmap-darwin-arm64
chmod +x jsmap-darwin-arm64
./jsmap-darwin-arm64 --help

# Windows
wget https://github.com/0xhkx0/jsmap/releases/download/v0.0.1/jsmap-windows-amd64.exe
jsmap-windows-amd64.exe --help
```

### Build from Source

```bash
git clone https://github.com/0xhkx0/jsmap.git
cd jsmap
go build -o jsmap ./cmd/jsmap
./jsmap --help
```

## Quick Start

### Analyze a JavaScript File
```bash
./jsmap -f sample.js
```

### Analyze a URL
```bash
./jsmap -u https://example.com/assets/app.js
```

### Crawl and Analyze Entire Website
```bash
./jsmap -u https://example.com -crawl -format json -o results.json
```

### Parse Raw HTTP Request
```bash
./jsmap -r burp_request.txt -format json
```

### Analyze Multiple URLs
```bash
./jsmap -ul targets.txt -o findings.csv -format csv
```

## Usage

```
jsmap - JavaScript Bug Bounty Scanner
Similar to sqlmap but for JavaScript analysis.

Usage:
  jsmap -u <url> [options]        # Fetch and analyze URL
  jsmap -u <url> -crawl [options] # Crawl URL for all JS files and analyze
  jsmap -r <request_file> [options] # Analyze HTTP request file
  jsmap -ul <url_list> [options]  # Analyze multiple URLs
  jsmap -f <js_file> [options]    # Analyze local JavaScript file

Input Options:
  -u <url>          Target URL to fetch and analyze
  -crawl            Auto-crawl URL to find and analyze all JS files
  -r <file>         HTTP request file (raw format or Burp export)
  -f <file>         Local JavaScript file
  -ul <file>        File with URLs (one per line)

Authentication Options:
  -cookie <string>  HTTP Cookie value
  -ua <string>      User-Agent (default: jsmap/1.0)

Request Options:
  -timeout <int>    Request timeout in seconds (default: 30)
  -proxy <url>      HTTP proxy URL for requests
  -t <int>          Concurrent requests (default: 1)

Output Options:
  -o <file>         Output file (prints to stdout if not specified)
  -format <fmt>     Output format: table, json, csv, html (default: table)
  -q                Quiet mode (suppress banner and non-critical output)
  -v                Verbose output (detailed logging)
```

## Examples

```bash
# Simple analysis of a JavaScript file
jsmap -f app.js

# Analyze with JSON output
jsmap -f app.js -format json

# Fetch and analyze from URL
jsmap -u https://target.com/app.js

# Crawl entire website and save results
jsmap -u https://target.com -crawl -o report.json -format json

# Crawl with custom timeout and concurrent requests
jsmap -u https://target.com -crawl -timeout 60 -t 5

# Analyze with authentication
jsmap -u https://target.com -crawl -cookie "session=abc123xyz" -format json

# Parse Burp request and generate HTML report
jsmap -r burp_export.txt -format html -o findings.html

# Batch process URLs with proxy
jsmap -ul targets.txt -proxy http://127.0.0.1:8080 -format csv -o results.csv

# Verbose output for debugging
jsmap -f app.js -v
```

## Architecture

jsmap is organized as a modular Go package with clean separation of concerns:

```
jsmap/
├── cmd/jsmap/          # CLI entry point
├── pkg/
│   ├── analyzer/       # Pattern detection engine
│   ├── client/         # HTTP client & request parsing
│   ├── crawler/        # JavaScript discovery
│   ├── output/         # Output formatting (table, JSON, CSV, HTML)
│   ├── sourcemap/      # Source map handling
│   └── types/          # Shared types & data structures
├── test/               # Test fixtures and utilities
├── docs/               # Detailed documentation
└── examples/           # Usage examples
```

### Package Details

- **analyzer**: Core pattern matching for endpoints, URLs, secrets, emails, and files
- **client**: HTTP client with Burp request parsing and cookie/header support
- **crawler**: Recursive JavaScript discovery with source map integration
- **output**: Multi-format output generation (table, JSON, CSV, HTML)
- **sourcemap**: Source map fetching and beautification
- **types**: Shared data types and aggregation logic

## Documentation

- [Features Guide](docs/FEATURES.md) - Detailed feature documentation
- [Complete Guide](docs/COMPLETE_GUIDE.md) - Comprehensive usage guide
- [CLI Reference](docs/README_CLI.md) - Complete CLI documentation

## Output Examples

### Table Format
```
╔═══════════════════════════════════════════════════════════════╗
║              JSMAP - BUG BOUNTY JAVASCRIPT SCANNER            ║
╚═══════════════════════════════════════════════════════════════╝

📍 API ENDPOINTS (3)
────────────────────────────────────────────────────────────────
  • /admin/dashboard
  • /api/v1/users
  • /auth/login

🔐 SECRETS (2)
────────────────────────────────────────────────────────────────
  ⚠️  eyJhbGciOi...sR8U (JWT)
  ⚠️  mongodb://...mydb (MongoDB)
```

### JSON Format
```json
{
  "sources": ["app.js"],
  "findings": {
    "endpoints": ["/admin/dashboard", "/api/v1/users"],
    "secrets": [
      {"type": "JWT", "value": "eyJhbGciOi..."},
      {"type": "MongoDB", "value": "mongodb://..."}
    ]
  }
}
```

## Supported Platforms

- Linux (amd64)
- macOS (amd64, arm64)
- Windows (amd64)

## Performance

- Concurrent request handling (configurable with `-t` flag)
- Efficient pattern matching with compiled regex
- Source map caching to minimize redundant requests
- Streaming output for large results

## Privacy & Security

- Local processing - no data sent to external services
- Source maps are fetched from the target server only
- Supports HTTP proxies for security scanning through proxies
- No telemetry or tracking

## License

Apache License 2.0 - See [LICENSE](LICENSE) file for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development

```bash
# Clone the repository
git clone https://github.com/0xhkx0/jsmap.git
cd jsmap

# Build
make build

# Test
make test

# Run with make
make run ARGS="-f test/fixtures/sample.js"
```

## Changelog

### v0.0.1 (Initial Release)

Initial release of jsmap with:
- Modular package architecture
- Pattern detection for APIs, URLs, secrets, emails, and files
- Source map support with beautification
- Multiple input formats (file, URL, crawl, batch)
- Multiple output formats (table, JSON, CSV, HTML)
- CLI with 12+ configuration options
- GitHub Actions release workflow

## Support & Contact

For issues, feature requests, or questions:
- Open an issue on [GitHub Issues](https://github.com/0xhkx0/jsmap/issues)
- Check existing documentation in the [docs](docs/) folder

## Disclaimer

jsmap is intended for authorized security testing and bug bounty programs only. Users are responsible for obtaining proper authorization before analyzing any JavaScript files or websites. Unauthorized access to computer systems is illegal.