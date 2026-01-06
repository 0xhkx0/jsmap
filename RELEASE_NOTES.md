# jsmap v0.0.1 - Initial Release

## Overview

jsmap is a comprehensive bug bounty JavaScript scanner designed to identify API endpoints, URLs, secrets, and other sensitive information embedded in JavaScript files.

## New Features

### Core Functionality
- **Pattern Detection**: Automatically identifies API endpoints, URLs, secrets, emails, and file references
- **Source Map Support**: Extracts and beautifies minified JavaScript using source maps
- **Multiple Input Methods**: Scan files, URLs, URL lists, or crawl entire websites
- **Flexible Output**: Table, JSON, CSV, and HTML report formats

### Package Structure
- `pkg/analyzer`: Core pattern matching engine for endpoints, URLs, secrets, and files
- `pkg/client`: HTTP client with Burp request parsing support
- `pkg/crawler`: Recursive JavaScript file discovery with source map integration
- `pkg/output`: Multi-format output generation
- `pkg/sourcemap`: Source map extraction and beautification
- `pkg/types`: Shared types and data aggregation

### CLI Features
- 12+ command-line flags for flexible scanning
- Cookie and custom header support
- Proxy configuration
- Timeout control
- Quiet mode for clean output
- Verbose logging for debugging

## Supported Platforms

- **Linux**: amd64
- **macOS**: amd64, arm64
- **Windows**: amd64

## Installation

Download the appropriate binary for your platform from the [releases page](https://github.com/0xhkx0/jsmap/releases).

```bash
chmod +x jsmap-*
./jsmap-* --help
```

## Quick Start

Scan a JavaScript file:
```bash
./jsmap -f sample.js
```

Scan a URL:
```bash
./jsmap -u https://example.com/assets/app.js
```

Crawl a website:
```bash
./jsmap -crawl https://example.com -format json -o results.json
```

## Documentation

- [Features Guide](../../docs/FEATURES.md)
- [Complete Guide](../../docs/COMPLETE_GUIDE.md)
- [CLI Reference](../../docs/README_CLI.md)

## License

Apache License 2.0 - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.
