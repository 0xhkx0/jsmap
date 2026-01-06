# jsmap - JavaScript Bug Bounty Scanner

A powerful sqlmap-inspired CLI tool for JavaScript static analysis. Extract API endpoints, URLs, secrets, and emails from JavaScript files with intelligent noise filtering. Supports local files, HTTP requests, URLs, and modern minified/bundled JavaScript.

## Features

✅ **Multiple Input Modes**
- Local JavaScript files
- Direct URLs (with auth headers & cookies)
- Raw HTTP requests (Burp/manual format)
- URL lists
- Minified & bundled JavaScript support

✅ **Comprehensive Detection**
- API Endpoints (/api/v1/*, /auth/*, /admin/*, etc.)
- URLs (Cloud storage, full URLs, WebSocket endpoints)
- Secrets (AWS Keys, Stripe, GitHub, JWT, DB connections)
- Emails
- File References (.sql, .env, .bak, etc.)

✅ **Smart Filtering**
- Detects minified code and beautifies automatically
- Filters noise (W3 namespaces, test domains, build artifacts)
- Deduplicates findings across multiple sources
- Tracks sources for each finding

✅ **Multiple Output Formats**
- Table (terminal-friendly with colors)
- JSON (machine-readable)
- CSV (for spreadsheets)
- HTML (professional reports)

✅ **Supports Modern Development**
- Next.js, Vite, webpack bundles
- Minified JS (.min.js)
- Bundled applications
- Authentication support (cookies, custom headers)

## Installation

```bash
git clone https://github.com/0xhkx0/jsmap.git
cd jsmap
go build -o jsmap main.go analyzer.go httpclient.go aggregated.go output.go
```

## Quick Start

### Analyze a local file
```bash
jsmap -f app.js
jsmap -f app.min.js -v  # Verbose with minified detection
```

### Fetch and analyze from URL
```bash
jsmap -u https://target.com/app.js
jsmap -u https://target.com/bundle.min.js -format json
```

### Analyze authenticated requests
```bash
jsmap -u https://api.target.com/app.js -cookie "session=abc123" -ua "Chrome/120"
```

### Parse raw HTTP request
```bash
jsmap -r request.txt -v
```

### Batch process multiple URLs
```bash
jsmap -ul targets.txt -o results.json -format json
```

## Usage Examples

### Example 1: Simple local file analysis
```bash
$ jsmap -f app.js

╔═══════════════════════════════════════════════════════════════════╗
║              JSMAP - BUG BOUNTY JAVASCRIPT SCANNER               ║
╚═══════════════════════════════════════════════════════════════════╝

📊 SOURCES (1)
  • app.js (Status: 200)

📍 API ENDPOINTS (5)
  • /admin/dashboard
  • /api/v1/users
  • /api/v2/auth
  • /auth/login
  • /auth/callback

🌐 URLS (2)
  • https://api.target.com/v1/data
  • https://bucket.s3.amazonaws.com/uploads

🔐 SECRETS (3) ⚠️  HIGH PRIORITY
  ⚠️  sk_live_4e...7890 (Stripe Live)
  ⚠️  AKIA...EXAMPLE (AWS Key)
  ⚠️  eyJhbGciOi...sR8U (JWT)

📧 EMAILS (2)
  • admin@target.com
  • security@target.com

📄 FILES (4)
  • database/backup.sql
  • .env.production
  • config/secrets.json
  • uploads/data.csv
```

### Example 2: Minified code detection
```bash
$ jsmap -f app.min.js -v

[*] Analyzing JS file: app.min.js
[*] Detected minified JavaScript
[+] Endpoint: /api/v1/users
[+] URL: https://api.example.com
[!] Secret: sk_live_***...***
...
```

### Example 3: JSON export for processing
```bash
$ jsmap -f app.js -format json -q | jq '.endpoints'

[
  "/admin/dashboard",
  "/api/v1/users",
  "/auth/login"
]
```

### Example 4: Authenticated request
```bash
$ cat request.txt
GET /app.js HTTP/1.1
Host: target.com
Cookie: session=secure123
Authorization: Bearer eyJhbGc...

$ jsmap -r request.txt -v
```

### Example 5: Generate HTML report
```bash
$ jsmap -u https://target.com/app.js -o report.html -format html
$ open report.html  # Opens in browser
```

### Example 6: Batch analysis with multiple URLs
```bash
$ cat targets.txt
https://target1.com/app.js
https://target2.com/bundle.js
https://target3.com/vendor.min.js

$ jsmap -ul targets.txt -o report.json -format json
[+] Results saved to: report.json
```

## Command-Line Options

```
Input Options:
  -u <url>          Target URL to fetch and analyze
  -r <file>         HTTP request file (raw format)
  -f <file>         Local JavaScript file
  -ul <file>        File with URLs (one per line)

Authentication Options:
  -cookie <string>  HTTP Cookie value
  -ua <string>      User-Agent (default: jsmap/1.0)

Request Options:
  -timeout <int>    Request timeout in seconds (default: 30)
  -proxy <url>      HTTP proxy URL
  -t <int>          Concurrent requests (default: 1)

Output Options:
  -o <file>         Output file
  -format <fmt>     Format: table, json, csv, html (default: table)
  -q                Quiet mode
  -v                Verbose output
```

## What It Detects

### API Endpoints
```
/api/v1/users              /api/users
/auth/login                /auth/callback
/oauth2/token              /graphql
/admin/dashboard           /admin/settings
/internal/config           /debug/logs
```

### URLs
```
https://api.example.com/v1/data
https://bucket.s3.amazonaws.com/uploads
https://storage.googleapis.com/data
wss://api.example.com/stream
```

### Secrets (High Priority)
```
AWS Keys (AKIA...)
Stripe Keys (sk_live_...)
GitHub Tokens (ghp_...)
JWT Tokens
MongoDB Connection Strings
PostgreSQL Connection Strings
Private Keys (PEM, EC)
Slack Tokens (xox...)
```

### Other Findings
```
Email addresses
Database backups
Configuration files
Source maps
Private keys
```

## Modern JavaScript Support

jsmap intelligently handles:
- ✅ Minified JavaScript (.min.js)
- ✅ Webpack bundles (main.js, chunk files)
- ✅ Vite builds (bundle.js, vendor.js)
- ✅ Next.js builds (_next/static/*)
- ✅ Concatenated/uglified code
- ✅ Obfuscated code

The analyzer auto-detects minification and applies beautification techniques to improve pattern matching accuracy.

## Output Formats

### Table Format (Default)
Human-readable terminal output with color indicators for high-priority findings.

### JSON Format
```json
{
  "sources": [{"name": "app.js", "status_code": 200}],
  "endpoints": {"/api/v1/users": {"count": 1, "sources": ["app.js"]}},
  "secrets": [{"value": "sk_***", "type": "Stripe", "source": "app.js"}],
  "summary": {"endpoints": 5, "urls": 2, "secrets": 3, "total": 10}
}
```

### CSV Format
```csv
Category,Value,Sources,Count
endpoint,/api/v1/users,app.js,1
secret,sk_live_***,app.js,1
email,admin@target.com,app.js,1
```

### HTML Format
Professional report with summary statistics and detailed findings table.

## Bug Bounty Workflow

```bash
# 1. Crawl target website with browser proxy
# 2. Capture JavaScript files
# 3. Run jsmap on all JS files
jsmap -f app.js -f bundle.js -f vendor.js

# 4. For authenticated areas
jsmap -u https://target.com/admin/app.js -cookie "admin_session=xyz"

# 5. Export findings
jsmap -u https://target.com/app.js -o report.html -format html

# 6. Review high-priority secrets and endpoints
# 7. Test for vulnerabilities (auth bypass, exposed endpoints, etc.)
```

## Development

Build from source:
```bash
go build -o jsmap main.go analyzer.go httpclient.go aggregated.go output.go
```

Run tests:
```bash
go test -v ./...
```

## License

MIT - See LICENSE file

## Disclaimer

This tool is for authorized security testing only. Ensure you have proper authorization before analyzing JavaScript files or running security scans on any systems.

## Author

Inspired by sqlmap. Created for modern bug bounty hunting on web applications using Next.js, Vite, and other modern frameworks.
