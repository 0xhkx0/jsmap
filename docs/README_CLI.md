# jsmap - JavaScript Static Analysis Tool

A high-performance CLI tool written in Go that analyzes JavaScript files to extract API endpoints, URLs, secrets, emails, and file references. Inspired by the Burp Suite extension JSAnalyzer with intelligent noise filtering to reduce false positives.

## Features

- **Endpoint Detection** - Finds API paths, REST endpoints, OAuth URLs, admin routes
- **URL Extraction** - Extracts full URLs including cloud storage (AWS S3, Azure, GCP)
- **Secret Scanning** - Detects API keys, tokens, credentials (AWS, Stripe, GitHub, Slack, JWT, MongoDB, PostgreSQL, etc.)
- **Email Extraction** - Finds email addresses in JavaScript code
- **File Detection** - Detects references to sensitive files (.sql, .csv, .env, .pdf, etc.)
- **Smart Filtering** - Removes noise from XML namespaces, module imports, build artifacts, and common false positives
- **Multiple Output Formats** - Table (terminal), JSON, CSV
- **Quiet Mode** - Easily pipe results to other tools
- **Verbose Mode** - Detailed analysis output

## Installation

### From Source

```bash
git clone https://github.com/0xhkx0/jsmap.git
cd jsmap
go build -o jsmap
```

Or using make:

```bash
make build
make install
```

### Requirements

- Go 1.21 or higher

## Usage

```bash
jsmap -f <file> [options]
```

### Options

```
  -f string
        JavaScript file to analyze (required)
  -o string
        Output JSON file (optional)
  -format string
        Output format: table, json, csv (default: table)
  -q    Quiet mode (only show findings)
  -v    Verbose output
```

### Examples

**Analyze a file and display results in table format:**
```bash
jsmap -f app.js
```

**Export findings to JSON:**
```bash
jsmap -f app.js -o results.json
```

**Output as JSON to stdout (great for piping):**
```bash
jsmap -f app.js -format json | jq '.endpoints'
```

**Export as CSV:**
```bash
jsmap -f app.js -format csv -o results.csv
```

**Verbose analysis:**
```bash
jsmap -f app.js -v
```

**Quiet mode (just results, no table formatting):**
```bash
jsmap -f app.js -format json -q
```

**Pipe to other tools:**
```bash
jsmap -f app.js -format json -q | jq '.endpoints | length'
```

## What It Detects

### Endpoints
| Pattern | Example |
|---------|---------|
| API paths | `/api/v1/users`, `/api/v2/auth` |
| REST endpoints | `/rest/data`, `/graphql` |
| OAuth/Auth | `/oauth2/token`, `/auth/login` |
| Admin routes | `/admin`, `/dashboard`, `/internal` |
| Sensitive paths | `/config`, `/backup`, `/private`, `/upload` |

### URLs
- Full URLs (http/https)
- WebSocket URLs (ws/wss)
- Cloud storage (AWS S3, Azure Blob, Google Cloud Storage)

### Secrets
- AWS API Keys (AKIA...)
- Google API Keys (AIza...)
- Stripe Keys (sk_live_...)
- GitHub Personal Access Tokens (ghp_...)
- Slack Tokens (xox...)
- JWT Tokens
- Private Keys (RSA, EC)
- Database Connection Strings (MongoDB, PostgreSQL)

### Emails
- Valid email addresses with filtering for common test domains

### Files
- Sensitive file references (.sql, .csv, .env, .bak, .key, .pem, etc.)

## Output Formats

### Table Format (Default)
```
╔═══════════════════════════════════════════════════════════════════╗
║                         JS ANALYSIS RESULTS                       ║
╚═══════════════════════════════════════════════════════════════════╝

📍 ENDPOINTS (5)
────────────────────────────────────────────────────────────────
  • /api/v1/users
  • /api/v2/auth
  ...
```

### JSON Format
```json
{
  "endpoints": [...],
  "urls": [...],
  "emails": [...],
  "files": [...],
  "secrets": [...],
  "summary": {
    "endpoints": 5,
    "urls": 3,
    ...
  }
}
```

### CSV Format
```csv
Category,Value,Source
endpoint,/api/v1/users,
url,https://api.example.com,
email,admin@example.com,
```

## Noise Filtering

jsmap uses intelligent filtering to minimize false positives:

- Excludes XML namespaces (w3.org, schemas.microsoft.com, etc.)
- Filters out module imports (./lib, ../utils, node_modules, etc.)
- Removes build artifacts (webpack, zone.js, etc.)
- Ignores locale files (en.js, en-gb.js)
- Filters PDF and Excel internal structures
- Excludes common test domains and placeholder values

## Performance

Processes large JavaScript files efficiently:
- Single-pass analysis using compiled regex patterns
- Memory-efficient string handling
- Parallel pattern matching where applicable

## Comparison with JSAnalyzer

| Feature | jsmap (Go) | JSAnalyzer (Python) |
|---------|-----------|-------------------|
| Platform | CLI | Burp Suite Extension |
| Performance | ⚡ Fast | Medium |
| Output Formats | JSON, CSV, Table | UI Table only |
| Piping Support | ✅ Yes | ❌ No |
| Installation | Simple (single binary) | Requires Jython, Burp |
| Batch Processing | ✅ Yes | Manual per-request |

## Development

### Build

```bash
make build
```

### Run with Development

```bash
make run ARGS="-f test.js -v"
```

### Clean Build Artifacts

```bash
make clean
```

## License

MIT - See LICENSE file for details

## Author

Ported to Go from the original [JSAnalyzer](https://github.com/0xhkx0/jsmap/tree/main/JSAnalyzer) Burp Suite extension by Jensec

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.

## Disclaimer

This tool is intended for authorized security testing only. Ensure you have proper authorization before analyzing JavaScript files or running security scans on any systems.
