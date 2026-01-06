package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/0xhkx0/jsmap/pkg/types"
)

// Analyzer performs JavaScript analysis
type Analyzer struct {
	verbose    bool
	isMinified bool
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(verbose bool) *Analyzer {
	return &Analyzer{verbose: verbose, isMinified: false}
}

// Analyze analyzes JavaScript content
func (a *Analyzer) Analyze(content string, source string) *types.Findings {
	findings := types.NewFindings(a.verbose)

	// Detect if minified
	a.isMinified = a.detectMinified(content)
	if a.verbose && a.isMinified {
		fmt.Printf("[*] Detected minified JavaScript\n")
	}

	// Extract endpoints
	a.extractEndpoints(content, source, findings)

	// Extract URLs
	a.extractURLs(content, source, findings)

	// Extract secrets
	a.extractSecrets(content, source, findings)

	// Extract emails
	a.extractEmails(content, source, findings)

	// Extract files
	a.extractFiles(content, source, findings)

	return findings
}

// extractEndpoints finds API endpoints
func (a *Analyzer) extractEndpoints(content string, source string, findings *types.Findings) {
	// Use beautified version for minified code
	searchContent := content
	if a.isMinified {
		searchContent = a.beautifyMinified(content)
	}
	patterns := []string{
		// API endpoints (supports quotes, backticks, and variable assignments)
		`["'\x60]((?:https?:)?//[^"'\x60]+/api/[a-zA-Z0-9/_-]+)["'\x60]`,
		`["'\x60](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["'\x60]`,
		`["'\x60](/v\d+/[a-zA-Z0-9/_-]{2,})["'\x60]`,
		`["'\x60](/rest/[a-zA-Z0-9/_-]{2,})["'\x60]`,
		`["'\x60](/graphql[a-zA-Z0-9/_-]*)["'\x60]`,

		// OAuth/Auth endpoints
		`["'\x60](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["'\x60]`,
		`["'\x60](/auth[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/login[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/logout[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/token[a-zA-Z0-9/_-]*)["'\x60]`,

		// Sensitive paths
		`["'\x60](/admin[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/dashboard[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/internal[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/debug[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/config[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/backup[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/private[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/upload[a-zA-Z0-9/_-]*)["'\x60]`,
		`["'\x60](/download[a-zA-Z0-9/_-]*)["'\x60]`,

		// Well-known paths
		`["'\x60](/\.well-known/[a-zA-Z0-9/_-]+)["'\x60]`,
		`["'\x60](/idp/[a-zA-Z0-9/_-]+)["'\x60]`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(searchContent, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				value := strings.TrimSpace(match[1])
				if a.isValidEndpoint(value) {
					key := "endpoints:" + value
					if !findings.SeenKeys[key] {
						findings.SeenKeys[key] = true
						findings.Endpoints[value] = true
						if a.verbose {
							fmt.Printf("[+] Endpoint: %s\n", value)
						}
					}
				}
			}
		}
	}
}

// extractURLs finds full URLs
func (a *Analyzer) extractURLs(content string, source string, findings *types.Findings) {
	// Use beautified version for minified code
	searchContent := content
	if a.isMinified {
		searchContent = a.beautifyMinified(content)
	}

	patterns := []string{
		`["'](https?://[^\s"'<>]{10,})["']`,
		`["'](wss?://[^\s"'<>]{10,})["']`,
		`["'](sftp://[^\s"'<>]{10,})["']`,
		`(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"'<>]*)`,
		`(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"'<>]*)`,
		`(https?://storage\.googleapis\.com/[^\s"'<>]*)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(searchContent, -1)
		for _, match := range matches {
			value := strings.TrimSpace(match[len(match)-1])
			if a.isValidURL(value) {
				key := "urls:" + value
				if !findings.SeenKeys[key] {
					findings.SeenKeys[key] = true
					findings.URLs[value] = true
					if a.verbose {
						fmt.Printf("[+] URL: %s\n", value)
					}
				}
			}
		}
	}
}

// extractSecrets finds API keys and tokens
func (a *Analyzer) extractSecrets(content string, source string, findings *types.Findings) {
	// Search in both original and beautified content
	searchContents := []string{content}
	if a.isMinified {
		searchContents = append(searchContents, a.beautifyMinified(content))
	}

	secretPatterns := map[string]string{
		`AKIA[0-9A-Z]{16}`:                                   "AWS Key",
		`AIza[0-9A-Za-z\-_]{35}`:                             "Google API",
		`sk_live_[0-9a-zA-Z]{24,}`:                           "Stripe Live",
		`ghp_[0-9a-zA-Z]{36}`:                                "GitHub PAT",
		`xox[baprs]-[0-9a-zA-Z\-]{10,48}`:                    "Slack Token",
		`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`: "JWT",
		`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`:           "Private Key",
		`mongodb(?:\+srv)?://[^\s"'<>]+`:                     "MongoDB",
		`postgres(?:ql)?://[^\s"'<>]+`:                       "PostgreSQL",
	}

	seenSecrets := make(map[string]bool)

	for _, searchContent := range searchContents {
		for pattern, secretType := range secretPatterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllString(searchContent, -1)
			for _, value := range matches {
				if seenSecrets[value] {
					continue
				}
				seenSecrets[value] = true

				if a.isValidSecret(value) {
					masked := value
					if len(value) > 20 {
						masked = value[:10] + "..." + value[len(value)-4:]
					}
					key := "secrets:" + masked
					if !findings.SeenKeys[key] {
						findings.SeenKeys[key] = true
						findings.Secrets = append(findings.Secrets, types.Finding{
							Category: "secrets",
							Value:    masked + " (" + secretType + ")",
							Source:   source,
						})
						if a.verbose {
							fmt.Printf("[!] Secret: %s (%s)\n", masked, secretType)
						}
					}
				}
			}
		}
	}
}

// extractEmails finds email addresses
func (a *Analyzer) extractEmails(content string, source string, findings *types.Findings) {
	// Search in both original and beautified content for better minified support
	searchContents := []string{content}
	if a.isMinified {
		searchContents = append(searchContents, a.beautifyMinified(content))
	}

	// Multiple patterns to catch different email formats
	patterns := []string{
		`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}`,                   // Standard
		`["']([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})["']`,        // Quoted
		`=["']([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})["']`,       // Variable assignment
	}

	seenEmails := make(map[string]bool)

	for _, searchContent := range searchContents {
		for _, pattern := range patterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllStringSubmatch(searchContent, -1)

			for _, match := range matches {
				// Get the email from capture group if exists, otherwise use full match
				var value string
				if len(match) > 1 && match[1] != "" {
					value = match[1]
				} else {
					value = match[0]
				}

				// Skip if already seen in this search
				if seenEmails[value] {
					continue
				}
				seenEmails[value] = true

				if a.isValidEmail(value) {
					key := "emails:" + value
					if !findings.SeenKeys[key] {
						findings.SeenKeys[key] = true
						findings.Emails[value] = true
						if a.verbose {
							fmt.Printf("[+] Email: %s\n", value)
						}
					}
				}
			}
		}
	}
}

// extractFiles finds file references
func (a *Analyzer) extractFiles(content string, source string, findings *types.Findings) {
	// Use beautified version for minified code
	searchContent := content
	if a.isMinified {
		searchContent = a.beautifyMinified(content)
	}

	// Support quotes, backticks (template literals)
	pattern := `["'\x60]([a-zA-Z0-9_/.-]+\.(?:sql|csv|xlsx|xls|json|xml|yaml|yml|txt|log|conf|config|cfg|ini|env|bak|backup|old|orig|copy|key|pem|crt|cer|p12|pfx|doc|docx|pdf|zip|tar|gz|rar|7z|sh|bat|ps1|py|rb|pl))["'\x60]`
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(searchContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			value := strings.TrimSpace(match[1])
			if a.isValidFile(value) {
				key := "files:" + value
				if !findings.SeenKeys[key] {
					findings.SeenKeys[key] = true
					findings.Files[value] = true
					if a.verbose {
						fmt.Printf("[+] File: %s\n", value)
					}
				}
			}
		}
	}
}

// Validation functions

// isValidEndpoint validates endpoint
func (a *Analyzer) isValidEndpoint(value string) bool {
	if len(value) < 3 {
		return false
	}

	// Reject common noise strings
	noiseStrings := map[string]bool{
		"http://":  true,
		"https://": true,
		"/a":       true,
		"/P":       true,
		"/R":       true,
		"/V":       true,
		"/W":       true,
	}

	if noiseStrings[value] {
		return false
	}

	// Check noise patterns
	noisePatterns := []string{
		`^\.\.?/`,                      // Starts with ./ or ../
		`^[a-z]{2}(-[a-z]{2})?\.js$`,  // Locale files
		`^[a-z]{2}(-[a-z]{2})?$`,      // Just locale
		`-xform$`,                      // Excel xform
		`^sha\d*$`,                     // Crypto modules
		`^aes$|^des$|^md5$`,            // Crypto
		`^/[A-Z][a-z]+\s`,             // PDF structures
		`^/[A-Z][a-z]+$`,              // PDF objects
		`^\d+ \d+ R$`,                  // PDF refs
		`^xl/`,                         // Excel internal
		`^docProps/`,                   // Doc properties
		`^_rels/`,                      // Relationships
		`^META-INF/`,                   // Manifest
		`\.xml$`,                       // XML files
		`^worksheets/`,                 // Worksheets
		`^theme/`,                      // Theme
		`^webpack`,                     // Bundler
		`^zone\.js$`,                   // JS modules
		`^readable-stream/`,            // Modules
		`^process/`,                    // Modules
		`^stream/`,                     // Modules
		`^buffer$`,                     // Modules
		`^events$`,                     // Modules
		`^util$`,                       // Modules
		`^path$`,                       // Modules
		`^\+`,                          // Starts with +
		`^\$\{`,                        // Template literal
		`^#`,                           // Fragment
		`^\?\ref=`,                     // Query param
		`^/[a-z]$`,                     // Single letter
		`^/[A-Z]$`,                     // Single letter
		`^http://$`,                    // Empty
		`_ngcontent`,                   // Angular
	}

	for _, pattern := range noisePatterns {
		if match, _ := regexp.MatchString(pattern, value); match {
			return false
		}
	}

	// Must start with / and have some path
	if !strings.HasPrefix(value, "/") {
		return false
	}

	// Skip if just single segments
	parts := strings.Split(value, "/")
	if len(parts) < 2 {
		return false
	}

	return true
}

// isValidURL validates URL
func (a *Analyzer) isValidURL(value string) bool {
	if len(value) < 15 {
		return false
	}

	valLower := strings.ToLower(value)

	// Check for noise domains
	noiseDomains := []string{
		"www.w3.org", "schemas.openxmlformats.org", "schemas.microsoft.com",
		"purl.org", "purl.oclc.org", "openoffice.org", "docs.oasis-open.org",
		"sheetjs.openxmlformats.org", "ns.adobe.com", "www.xml.org",
		"example.com", "test.com", "localhost", "127.0.0.1",
		"fusioncharts.com", "jspdf.default.namespaceuri",
		"npmjs.org", "registry.npmjs.org",
		"github.com/indutny", "github.com/crypto-browserify",
		"jqwidgets.com", "ag-grid.com",
	}

	for _, domain := range noiseDomains {
		if strings.Contains(valLower, domain) {
			return false
		}
	}

	// Skip if contains placeholder patterns
	if strings.Contains(value, "{") || strings.Contains(valLower, "undefined") || strings.Contains(valLower, "null") {
		return false
	}

	// Skip data URIs
	if strings.HasPrefix(valLower, "data:") {
		return false
	}

	// Skip common static extensions
	staticExts := []string{".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ttf"}
	for _, ext := range staticExts {
		if strings.HasSuffix(valLower, ext) {
			return false
		}
	}

	return true
}

// isValidSecret validates secret
func (a *Analyzer) isValidSecret(value string) bool {
	if len(value) < 10 {
		return false
	}

	valLower := strings.ToLower(value)
	noiseWords := []string{"example", "placeholder", "your", "xxxx", "test"}

	for _, word := range noiseWords {
		if strings.Contains(valLower, word) {
			return false
		}
	}

	return true
}

// detectMinified checks if JavaScript is minified
func (a *Analyzer) detectMinified(content string) bool {
	// Check various indicators of minification
	lines := strings.Split(content, "\n")
	
	// Minified files typically have very few lines with very long content
	if len(lines) < 3 && len(content) > 5000 {
		return true
	}
	
	// Check if most lines are very long (> 200 chars)
	longLines := 0
	nonEmptyLines := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			nonEmptyLines++
			if len(line) > 200 {
				longLines++
			}
		}
	}
	
	if nonEmptyLines > 0 && longLines > nonEmptyLines*2/3 {
		return true
	}
	
	// Check for lack of meaningful comments and spacing
	commentLines := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			commentLines++
		}
	}
	
	// Minified code usually has few comments
	if nonEmptyLines > 10 && commentLines < nonEmptyLines/10 {
		if len(content) > 10000 {
			return true
		}
	}
	
	return false
}

// beautifyMinified adds spaces for better pattern matching in minified code
func (a *Analyzer) beautifyMinified(content string) string {
	// Add spaces around common delimiters in minified code to help pattern matching
	beautified := content
	
	// Add space after quotes that precede paths
	beautified = regexp.MustCompile(`"(/[^"]*?)"`).ReplaceAllString(beautified, `" $1 "`)
	beautified = regexp.MustCompile(`'(/[^']*?)'`).ReplaceAllString(beautified, `' $1 '`)
	
	// Add space after colons (for JSON properties)
	beautified = strings.ReplaceAll(beautified, "\":", "\" : ")
	beautified = strings.ReplaceAll(beautified, "':", "' : ")
	
	// Add spaces around common API patterns
	beautified = strings.ReplaceAll(beautified, "/api/", " /api/ ")
	beautified = strings.ReplaceAll(beautified, "/auth/", " /auth/ ")
	beautified = strings.ReplaceAll(beautified, "/admin/", " /admin/ ")
	beautified = strings.ReplaceAll(beautified, "/v1/", " /v1/ ")
	beautified = strings.ReplaceAll(beautified, "/v2/", " /v2/ ")
	beautified = strings.ReplaceAll(beautified, "/oauth", " /oauth ")
	beautified = strings.ReplaceAll(beautified, "/login", " /login ")
	beautified = strings.ReplaceAll(beautified, "/auth", " /auth ")
	beautified = strings.ReplaceAll(beautified, "/upload", " /upload ")
	beautified = strings.ReplaceAll(beautified, "/download", " /download ")
	beautified = strings.ReplaceAll(beautified, "/config", " /config ")
	beautified = strings.ReplaceAll(beautified, "/admin", " /admin ")
	beautified = strings.ReplaceAll(beautified, "/dashboard", " /dashboard ")
	beautified = strings.ReplaceAll(beautified, "@", " @ ")
	
	// Add newlines to help split patterns
	beautified = strings.ReplaceAll(beautified, ";", ";\n")
	beautified = strings.ReplaceAll(beautified, ",", ",\n")
	
	return beautified
}

// isValidEmail validates email
func (a *Analyzer) isValidEmail(value string) bool {
	if !strings.Contains(value, "@") {
		return false
	}

	valLower := strings.ToLower(value)
	parts := strings.Split(value, "@")
	if len(parts) < 2 {
		return false
	}
	domain := strings.ToLower(parts[len(parts)-1])

	excludedDomains := map[string]bool{
		"example.com":       true,
		"test.com":          true,
		"domain.com":        true,
		"placeholder.com":   true,
	}

	if excludedDomains[domain] {
		return false
	}

	noiseWords := []string{"example", "test", "placeholder", "noreply"}
	for _, word := range noiseWords {
		if strings.Contains(valLower, word) {
			return false
		}
	}

	return true
}

// isValidFile validates file reference
func (a *Analyzer) isValidFile(value string) bool {
	if len(value) < 3 {
		return false
	}

	valLower := strings.ToLower(value)

	// Skip common JS/build files
	noisePatterns := []string{
		"package.json", "tsconfig.json", "webpack", "babel",
		"eslint", "prettier", "node_modules", ".min.",
		"polyfill", "vendor", "chunk", "bundle",
	}

	for _, pattern := range noisePatterns {
		if strings.Contains(valLower, pattern) {
			return false
		}
	}

	// Skip source maps
	if strings.HasSuffix(valLower, ".map") {
		return false
	}

	// Skip common locale/language files
	if strings.HasSuffix(valLower, ".json") {
		lastPart := value[strings.LastIndex(value, "/")+1:]
		if len(lastPart) <= 7 {
			return false
		}
	}

	return true
}
