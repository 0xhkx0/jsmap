package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/0xhkx0/jsmap/pkg/analyzer"
	"github.com/0xhkx0/jsmap/pkg/client"
	"github.com/0xhkx0/jsmap/pkg/crawler"
	"github.com/0xhkx0/jsmap/pkg/output"
	"github.com/0xhkx0/jsmap/pkg/types"
)

func main() {
	// Define CLI flags
	urlInput := flag.String("u", "", "Target URL to analyze")
	requestFile := flag.String("r", "", "HTTP request file (raw format or Burp XML/JSON)")
	jsFile := flag.String("f", "", "JavaScript file to analyze")
	urlList := flag.String("ul", "", "File containing list of URLs (one per line)")
	crawlFlag := flag.Bool("crawl", false, "Auto-crawl URL to find and analyze all JS files")
	outputFile := flag.String("o", "", "Output file (JSON, CSV, or HTML)")
	format := flag.String("format", "table", "Output format: table, json, csv, html")
	cookie := flag.String("cookie", "", "HTTP Cookie header value")
	userAgent := flag.String("ua", "jsmap/1.0", "User-Agent header")
	timeout := flag.Int("timeout", 30, "Request timeout in seconds")
	proxy := flag.String("proxy", "", "HTTP proxy URL (e.g., http://127.0.0.1:8080)")
	quiet := flag.Bool("q", false, "Quiet mode")
	verbose := flag.Bool("v", false, "Verbose output")
	threaded := flag.Int("t", 1, "Number of concurrent requests")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `jsmap - JavaScript Bug Bounty Scanner
Similar to sqlmap but for JavaScript analysis. Extract APIs, secrets, and findings
from both authenticated and unauthenticated requests.

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
  -o <file>         Output file
  -format <fmt>     Output format: table, json, csv, html (default: table)
  -q                Quiet mode (suppress output)
  -v                Verbose output

Examples:
  jsmap -u https://target.com/app.js
  jsmap -u https://target.com -crawl              # Crawl and analyze all JS
  jsmap -u https://target.com -crawl -format json # Crawl, get JSON output
  jsmap -r request.txt -cookie "session=abc123"
  jsmap -ul targets.txt -o results.json
  jsmap -f app.js -format json -q
  jsmap -u https://api.target.com -proxy http://127.0.0.1:8080 -v
`)
	}

	flag.Parse()

	// Validate input
	inputCount := 0
	if *urlInput != "" {
		inputCount++
	}
	if *requestFile != "" {
		inputCount++
	}
	if *jsFile != "" {
		inputCount++
	}
	if *urlList != "" {
		inputCount++
	}

	if inputCount == 0 {
		fmt.Fprintf(os.Stderr, "Error: Provide at least one input (-u, -r, -f, or -ul)\n")
		flag.Usage()
		os.Exit(1)
	}

	if inputCount > 1 {
		fmt.Fprintf(os.Stderr, "Error: Provide only one input type (-u, -r, -f, or -ul)\n")
		flag.Usage()
		os.Exit(1)
	}

	// Setup HTTP client
	httpClient := client.New(&client.Config{
		UserAgent: *userAgent,
		Cookie:    *cookie,
		Timeout:   *timeout,
		ProxyURL:  *proxy,
		Verbose:   *verbose,
	})

	// Create aggregated findings
	allFindings := types.NewAggregatedFindings()
	jsAnalyzer := analyzer.NewAnalyzer(*verbose)

	// Process input
	switch {
	case *urlInput != "" && *crawlFlag:
		if !*quiet && *verbose {
			fmt.Printf("[*] Crawling URL: %s\n", *urlInput)
		}
		if err := processCrawl(*urlInput, httpClient, jsAnalyzer, allFindings, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case *urlInput != "":
		if !*quiet && *verbose {
			fmt.Printf("[*] Fetching URL: %s\n", *urlInput)
		}
		if err := processURL(*urlInput, httpClient, jsAnalyzer, allFindings); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case *urlList != "":
		if !*quiet && *verbose {
			fmt.Printf("[*] Reading URL list: %s\n", *urlList)
		}
		if err := processURLList(*urlList, httpClient, jsAnalyzer, allFindings, *threaded); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case *requestFile != "":
		if !*quiet && *verbose {
			fmt.Printf("[*] Processing request file: %s\n", *requestFile)
		}
		if err := processRequestFile(*requestFile, httpClient, jsAnalyzer, allFindings, *crawlFlag, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case *jsFile != "":
		if !*quiet && *verbose {
			fmt.Printf("[*] Analyzing JS file: %s\n", *jsFile)
		}
		content, err := os.ReadFile(*jsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		findings := jsAnalyzer.Analyze(string(content), *jsFile)
		allFindings.AddFindings(findings, *jsFile, "", 200)
	}

	if !*quiet && *verbose {
		fmt.Printf("[+] Total findings: %d\n", len(allFindings.Endpoints)+len(allFindings.URLs)+len(allFindings.Secrets)+len(allFindings.Emails)+len(allFindings.Files))
	}

	// Output results
	var outputStr string
	switch *format {
	case "json":
		outputStr = output.AggregatedToJSON(allFindings)
	case "csv":
		outputStr = output.AggregatedToCSV(allFindings)
	case "html":
		outputStr = output.AggregatedToHTML(allFindings)
	default: // table
		outputStr = output.AggregatedToTable(allFindings)
	}

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(outputStr), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		if !*quiet {
			fmt.Printf("[+] Results saved to: %s\n", *outputFile)
		}
	} else if !*quiet {
		fmt.Println(outputStr)
	}
}

// processURL analyzes a single URL
func processURL(targetURL string, httpClient *client.HTTPClient, jsAnalyzer *analyzer.Analyzer, allFindings *types.AggregatedFindings) error {
	content, statusCode, err := httpClient.FetchURL(targetURL)
	if err != nil {
		return err
	}

	findings := jsAnalyzer.Analyze(content, targetURL)
	allFindings.AddFindings(findings, targetURL, targetURL, statusCode)

	return nil
}

// processURLList reads and processes multiple URLs
func processURLList(filePath string, httpClient *client.HTTPClient, jsAnalyzer *analyzer.Analyzer, allFindings *types.AggregatedFindings, threads int) error {
	urls, err := client.ReadURLList(filePath)
	if err != nil {
		return err
	}

	for _, url := range urls {
		if err := processURL(url, httpClient, jsAnalyzer, allFindings); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", url, err)
		}
	}

	return nil
}

// processRequestFile handles raw HTTP request files
func processRequestFile(filePath string, httpClient *client.HTTPClient, jsAnalyzer *analyzer.Analyzer, allFindings *types.AggregatedFindings, crawl bool, verbose bool) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	contentStr := string(content)

	// Parse raw HTTP request
	method, targetURL, _, headers, err := client.ParseRawRequest(contentStr)
	if err != nil {
		return err
	}

	if method != "GET" && method != "get" {
		fmt.Printf("[!] Note: Request uses %s method, fetching as GET\n", method)
	}

	// Create request with custom headers
	req, _ := http.NewRequest("GET", targetURL, nil)
	for k, v := range headers {
		if strings.ToLower(k) != "host" && strings.ToLower(k) != "content-length" {
			req.Header.Set(k, v)
		}
	}

	resp, err := httpClient.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	htmlContent := string(body)

	// Check if response is HTML and crawl for JS files if enabled
	if crawl && (strings.Contains(htmlContent, "<script") || strings.Contains(htmlContent, ".js")) {
		if verbose {
			fmt.Printf("[*] HTML response detected, crawling for JavaScript files...\n")
		}

		// Create crawler config
		crawlConfig := &crawler.Config{
			TargetURL:  targetURL,
			HTTPClient: httpClient.Client,
			FetchURL:   httpClient.FetchURL,
			Verbose:    verbose,
		}

		jsFiles, err := crawler.CrawlForJavaScript(crawlConfig)
		if err != nil {
			if verbose {
				fmt.Printf("[!] Crawl error: %v\n", err)
			}
		}

		if len(jsFiles) > 0 {
			if verbose {
				fmt.Printf("[*] Analyzing %d JavaScript files from crawl...\n", len(jsFiles))
			}

			for _, jsFile := range jsFiles {
				jsFindings := jsAnalyzer.Analyze(jsFile.Content, jsFile.URL)
				allFindings.AddFindings(jsFindings, jsFile.FileName, jsFile.URL, 200)
			}
		}
	}

	// Also analyze the original HTML response
	findings := jsAnalyzer.Analyze(htmlContent, targetURL)
	allFindings.AddFindings(findings, targetURL, targetURL, resp.StatusCode)

	return nil
}

// processCrawl crawls a URL to find and analyze all JavaScript files
func processCrawl(targetURL string, httpClient *client.HTTPClient, jsAnalyzer *analyzer.Analyzer, allFindings *types.AggregatedFindings, verbose bool) error {
	crawlConfig := &crawler.Config{
		TargetURL:       targetURL,
		HTTPClient:      httpClient.Client,
		FetchURL:        httpClient.FetchURL,
		IncludeExternal: false,
		Verbose:         verbose,
	}

	jsFiles, err := crawler.CrawlForJavaScript(crawlConfig)
	if err != nil {
		return err
	}

	if verbose {
		fmt.Printf("[*] Analyzing %d JavaScript files...\n", len(jsFiles))
	}

	for _, jsFile := range jsFiles {
		findings := jsAnalyzer.Analyze(jsFile.Content, jsFile.URL)
		allFindings.AddFindings(findings, jsFile.URL, jsFile.URL, 200)
	}

	return nil
}
