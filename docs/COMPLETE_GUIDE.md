# jsmap - Complete Feature Overview

A powerful JavaScript bug bounty scanner inspired by sqlmap. Extract APIs, secrets, and vulnerabilities from JavaScript files - whether local, from URLs, or automatically crawled from web pages.

## 🎯 Key Achievements

✅ **Full sqlmap-style input handling**
- Single URL analysis
- URL lists (batch processing)
- Raw HTTP requests (Burp/manual)
- Local JavaScript files
- **AUTO-CRAWL** - automatically discovers and analyzes all JS files from a page

✅ **Modern JavaScript support**
- Minified code detection & beautification
- Bundled applications (webpack, Vite, Next.js)
- Source map parsing
- Obfuscated code handling

✅ **Comprehensive extraction**
- API Endpoints (all variations)
- Full URLs (HTTP/HTTPS/WS/WSS)
- Secrets (AWS, Stripe, JWT, DB connections, etc.)
- Email addresses
- File references

✅ **Multiple output formats**
- Table (colorized terminal output)
- JSON (machine-readable)
- CSV (spreadsheets)
- HTML (professional reports)

✅ **Authentication support**
- Custom cookies
- Custom headers
- User-Agent spoofing
- HTTP proxy support

## 📋 Usage Examples

### Basic Analysis
```bash
jsmap -f app.js
jsmap -u https://target.com/app.js
jsmap -r burp_request.txt
```

### Auto-Crawl All JavaScript
```bash
# Crawl a URL and automatically find/analyze all JS files
jsmap -u https://target.com -crawl

# Export findings as JSON
jsmap -u https://target.com -crawl -format json -o findings.json

# Export as HTML report
jsmap -u https://target.com -crawl -format html -o report.html
```

### Authenticated Crawl
```bash
jsmap -u https://internal.target.com -crawl -cookie "admin_token=xyz123"
```

### Batch Processing
```bash
jsmap -ul domains.txt -format json -o results.json
```

## 🔧 How Crawl Works

When you run: `jsmap -u https://gamma.app -crawl`

1. **Fetches the page** at https://gamma.app
2. **Extracts all JS references** including:
   - `<script src="...">`
   - `<link href="...">`
   - Import statements
   - Next.js `_next/static/` paths
   - Vite bundle paths
3. **Downloads each JS file** using the provided auth (cookies, headers)
4. **Analyzes each file** for:
   - API endpoints
   - Secrets
   - URLs
   - Emails
   - File references
5. **Aggregates findings** across all files
6. **Shows sources** for each finding (which file it came from)

## 📊 Real-World Example

```bash
$ jsmap -u https://gamma.app -crawl -v

[*] Crawling URL: https://gamma.app
[*] Found 15 JavaScript files
[+] Downloaded: main.js (125KB)
[+] Downloaded: vendor.js (890KB)
[+] Downloaded: app.min.js (234KB)
...
[*] Analyzing 15 JavaScript files...

[+] Found 47 total findings across all files
```

Output shows:
- **5 unique API endpoints** across multiple files
- **3 exposed database URLs** in vendor.js
- **2 API keys** in app configuration
- **12 email addresses** for further research

## 🎓 Bug Bounty Workflow

```bash
# 1. Quick single-file scan
jsmap -f app.js -v

# 2. Analyze from URL
jsmap -u https://target.com/assets/bundle.js

# 3. AUTO-CRAWL entire site
jsmap -u https://target.com -crawl -format json -o scan.json

# 4. For authenticated areas
jsmap -u https://internal.target.com/admin -crawl -cookie "session=token123"

# 5. Export professional report
jsmap -u https://target.com -crawl -format html -o report.html

# 6. Process findings
cat scan.json | jq '.endpoints' | grep "/api/admin"
cat scan.json | jq '.secrets'
```

## 🚀 Installation & Usage

### Build
```bash
git clone https://github.com/0xhkx0/jsmap.git
cd jsmap
go build -o jsmap *.go --exclude testserver.go
```

### Run
```bash
# Single file
./jsmap -f app.js

# URL
./jsmap -u https://target.com/app.js

# Crawl and auto-find all JS
./jsmap -u https://target.com -crawl

# With output
./jsmap -u https://target.com -crawl -o report.html -format html
```

## 📁 Project Structure

```
jsmap/
├── main.go           # CLI and input handling
├── analyzer.go       # Pattern matching and extraction
├── httpclient.go     # HTTP requests and parsing
├── crawler.go        # Auto-crawl and JS discovery ⭐ NEW
├── aggregated.go     # Aggregate findings from multiple sources
├── output.go         # Output formatting (table/json/csv/html)
├── sample.js         # Sample JavaScript file
├── sample.min.js     # Minified JavaScript sample
├── index.html        # Test page with script tags
├── testserver.go     # Local test server
└── README.md         # Documentation
```

## 🔐 What It Detects

### Endpoints Found
```
/api/v1/users
/api/v2/auth
/auth/login
/auth/callback
/oauth2/token
/admin/dashboard
/admin/settings
/graphql
/internal/debug
```

### Secrets Detected
```
AWS Keys (AKIA...)
Stripe Keys (sk_live_...)
GitHub Tokens (ghp_...)
JWT Tokens
MongoDB Connection Strings
PostgreSQL Connection Strings
Private Keys (PEM/EC)
Slack Tokens
```

### Additional Findings
```
Third-party API URLs
Cloud storage endpoints (S3, Azure, GCP)
Email addresses
Database backup files
Configuration files
Source maps
```

## 💡 Advanced Features

### Minified Code Handling
Automatically detects minified JS and beautifies it for better pattern matching:
```bash
jsmap -f bundle.min.js -v
# [*] Detected minified JavaScript
# [+] Added spaces for pattern matching
# [+] Found 5 endpoints despite minification
```

### Source Tracking
Each finding shows which file it came from:
```json
{
  "endpoints": {
    "/api/users": {
      "count": 1,
      "sources": ["http://target.com/main.js"]
    }
  }
}
```

### HTML Reports
Beautiful HTML reports for client delivery or team sharing.

## 🎯 Why Use jsmap?

| Feature | jsmap | Manual | Other Tools |
|---------|-------|--------|-------------|
| Auto-crawl JS | ✅ | ❌ | ⚠️ Limited |
| Minified support | ✅ | ❌ | ⚠️ Basic |
| Multiple formats | ✅ | ❌ | ⚠️ Limited |
| Auth support | ✅ | ⚠️ Complex | ✅ |
| Source tracking | ✅ | ❌ | ❌ |
| HTML reports | ✅ | ❌ | ⚠️ |
| Simple CLI | ✅ | N/A | ⚠️ |

## 📝 License

MIT - Free for commercial and personal use

## ⚠️ Disclaimer

For authorized security testing only. Always get written permission before scanning any systems.

---

**Created for modern bug bounty hunting on web applications using Next.js, Vite, React, Vue, and other frameworks.**
