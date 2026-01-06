package crawler

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/0xhkx0/jsmap/pkg/sourcemap"
)

// Config holds crawl configuration
type Config struct {
	TargetURL       string
	HTTPClient      *http.Client
	FetchURL        func(string) (string, int, error)
	IncludeExternal bool
	Verbose         bool
}

// JavaScriptFile represents a discovered JS file
type JavaScriptFile struct {
	URL      string
	FileName string
	Content  string
}

// CrawlForJavaScript discovers and downloads all JS files from a URL
func CrawlForJavaScript(config *Config) ([]JavaScriptFile, error) {
	var jsFiles []JavaScriptFile
	seenURLs := make(map[string]bool)
	queue := []string{}

	if config.Verbose {
		fmt.Printf("[*] Crawling: %s\n", config.TargetURL)
	}

	// Fetch the HTML page
	htmlContent, statusCode, err := config.FetchURL(config.TargetURL)
	if err != nil {
		return nil, err
	}

	if config.Verbose {
		fmt.Printf("[*] Page status: %d, size: %d bytes\n", statusCode, len(htmlContent))
	}

	// Extract script sources from HTML
	jsURLs := extractJavaScriptSources(htmlContent, config.TargetURL)
	queue = append(queue, jsURLs...)

	if config.Verbose {
		fmt.Printf("[*] Found %d JavaScript files in HTML\n", len(jsURLs))
	}

	baseURLObj, _ := url.Parse(config.TargetURL)

	// Process queue (BFS for JS files)
	for len(queue) > 0 {
		jsURL := queue[0]
		queue = queue[1:]

		// Skip if already processed
		if seenURLs[jsURL] {
			continue
		}
		seenURLs[jsURL] = true

		if config.Verbose {
			fmt.Printf("[*] Fetching JS: %s\n", jsURL)
		}

		content, _, err := config.FetchURL(jsURL)
		if err != nil {
			if config.Verbose {
				fmt.Printf("[!] Error fetching %s: %v\n", jsURL, err)
			}
			continue
		}

		// Extract filename
		fileName := extractFileName(jsURL)

		jsFiles = append(jsFiles, JavaScriptFile{
			URL:      jsURL,
			FileName: fileName,
			Content:  content,
		})

		if config.Verbose {
			fmt.Printf("[+] Downloaded: %s (%d bytes)\n", fileName, len(content))
		}

		// Try to fetch source map for better analysis
		sourceMap, err := sourcemap.FetchSourceMap(jsURL, config.HTTPClient, config.Verbose)
		if err == nil && sourceMap != nil {
			originalSource := sourcemap.ExtractOriginalSource(sourceMap)
			if originalSource != "" {
				// Add original source as additional file for analysis
				jsFiles = append(jsFiles, JavaScriptFile{
					URL:      jsURL + ".map.original",
					FileName: fileName + ".original",
					Content:  originalSource,
				})
				if config.Verbose {
					fmt.Printf("[+] Extracted original source from source map (%d bytes)\n", len(originalSource))
				}
			}
		}

		// RECURSIVE: Extract more JS files from this JS file
		newJSURLs := extractJSFromJSContent(content, jsURL, baseURLObj)
		if len(newJSURLs) > 0 {
			if config.Verbose {
				fmt.Printf("[*] Found %d additional JS files referenced in %s\n", len(newJSURLs), fileName)
			}
			for _, newURL := range newJSURLs {
				if !seenURLs[newURL] {
					queue = append(queue, newURL)
				}
			}
		}
	}

	if config.Verbose {
		fmt.Printf("[*] Total JavaScript files discovered: %d\n", len(jsFiles))
	}

	return jsFiles, nil
}

// extractJavaScriptSources extracts all JS file URLs from HTML
func extractJavaScriptSources(htmlContent, baseURL string) []string {
	var jsURLs []string
	seenURLs := make(map[string]bool)

	baseURLObj, _ := url.Parse(baseURL)

	// Pattern 1: <script src="...">
	scriptSrcPattern := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptSrcPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, baseURLObj)

			if jsURL != "" && !seenURLs[jsURL] {
				seenURLs[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	// Pattern 2: <link rel="modulepreload" href="..."> (for modern JS bundles)
	modulePattern := regexp.MustCompile(`<link[^>]+href=["']([^"']+\.js)["']`)
	matches = modulePattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, baseURLObj)

			if jsURL != "" && !seenURLs[jsURL] {
				seenURLs[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	// Pattern 3: import statements (commented out or in scripts)
	importPattern := regexp.MustCompile(`(?:import|from)\s+["']([^"']+\.js)["']`)
	matches = importPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, baseURLObj)

			if jsURL != "" && !seenURLs[jsURL] {
				seenURLs[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	// Pattern 4: Next.js _next/static/ paths
	nextPattern := regexp.MustCompile(`["'](_next/static/[^"']+\.js)["']`)
	matches = nextPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, baseURLObj)

			if jsURL != "" && !seenURLs[jsURL] {
				seenURLs[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	// Pattern 5: Vite/React/Vue bundle paths
	bundlePattern := regexp.MustCompile(`["'](/[^"']*(?:bundle|main|app|vendor|chunk)[^"']*\.js)["']`)
	matches = bundlePattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, baseURLObj)

			if jsURL != "" && !seenURLs[jsURL] {
				seenURLs[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	return jsURLs
}

// ResolveURL converts relative URLs to absolute URLs
func ResolveURL(rawURL string, baseURL *url.URL) string {
	rawURL = strings.TrimSpace(rawURL)

	// Skip empty or invalid URLs
	if rawURL == "" || strings.HasPrefix(rawURL, "data:") {
		return ""
	}

	// Already absolute URL
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		return rawURL
	}

	// Protocol-relative URL
	if strings.HasPrefix(rawURL, "//") {
		return baseURL.Scheme + ":" + rawURL
	}

	// Relative path
	if baseURL != nil {
		resolved, err := baseURL.Parse(rawURL)
		if err == nil {
			return resolved.String()
		}
	}

	return ""
}

// extractJSFromJSContent extracts JS file references from within JS content
func extractJSFromJSContent(jsContent, sourceURL string, baseURL *url.URL) []string {
	var jsURLs []string
	seenURLs := make(map[string]bool)

	// Determine the base URL from the source JS file
	sourceURLObj, err := url.Parse(sourceURL)
	if err != nil {
		sourceURLObj = baseURL
	}

	// Pattern 1: Webpack/Vite chunk loading - e.g., "chunk.abc123.js"
	chunkPattern := regexp.MustCompile(`["']([^"']*(?:chunk|vendor|main|app|runtime)[^"']*\.js)["']`)
	matches := chunkPattern.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, sourceURLObj)

			if jsURL != "" && !seenURLs[jsURL] && strings.HasSuffix(jsURL, ".js") {
				seenURLs[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	// Pattern 2: Dynamic imports - import("./module.js")
	dynamicImportPattern := regexp.MustCompile(`import\s*\(\s*["']([^"']+\.js)["']\s*\)`)
	matches = dynamicImportPattern.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, sourceURLObj)

			if jsURL != "" && !seenURLs[jsURL] {
				seenURLs[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	// Pattern 3: Script injection - document.createElement('script').src = "..."
	scriptCreatePattern := regexp.MustCompile(`\.src\s*=\s*["']([^"']+\.js)["']`)
	matches = scriptCreatePattern.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, sourceURLObj)

			if jsURL != "" && !seenURLs[jsURL] {
				seenURLs[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	// Pattern 4: Service worker registration - navigator.serviceWorker.register("sw.js")
	swPattern := regexp.MustCompile(`\.register\s*\(\s*["']([^"']+\.js)["']`)
	matches = swPattern.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, sourceURLObj)

			if jsURL != "" && !seenURLs[jsURL] {
				seenURLs[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	// Pattern 5: Absolute/relative paths in strings that look like JS files
	// Only match paths from same domain to avoid false positives
	pathPattern := regexp.MustCompile(`["'](/[^"'\s]*\.js(?:\?[^"']*)?)["']`)
	matches = pathPattern.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			jsURL := strings.TrimSpace(match[1])
			jsURL = ResolveURL(jsURL, sourceURLObj)

			if jsURL != "" && !seenURLs[jsURL] {
				// Only include if from same domain to reduce noise
				if isSameDomain(jsURL, sourceURL) {
					seenURLs[jsURL] = true
					jsURLs = append(jsURLs, jsURL)
				}
			}
		}
	}

	return jsURLs
}

// isSameDomain checks if two URLs are from the same domain
func isSameDomain(url1, url2 string) bool {
	u1, err1 := url.Parse(url1)
	u2, err2 := url.Parse(url2)

	if err1 != nil || err2 != nil {
		return false
	}

	return u1.Host == u2.Host
}

// extractFileName extracts filename from URL
func extractFileName(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "unknown.js"
	}

	path := parsedURL.Path
	if path == "" {
		path = parsedURL.RawQuery
	}

	parts := strings.Split(path, "/")
	fileName := parts[len(parts)-1]

	if fileName == "" {
		fileName = "index.js"
	}

	return fileName
}
