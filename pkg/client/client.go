package client

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config holds HTTP client configuration
type Config struct {
	UserAgent string
	Cookie    string
	Timeout   int
	ProxyURL  string
	Headers   map[string]string
	Verbose   bool
}

// HTTPClient wraps http.Client with custom configuration
type HTTPClient struct {
	Client *http.Client
	Config *Config
}

// New creates a new HTTP client
func New(config *Config) *HTTPClient {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: time.Duration(config.Timeout) * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: time.Duration(config.Timeout) * time.Second,
	}

	// Setup proxy if provided
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}

	return &HTTPClient{
		Client: httpClient,
		Config: config,
	}
}

// FetchURL fetches content from a URL
func (hc *HTTPClient) FetchURL(targetURL string) (string, int, error) {
	if hc.Config.Verbose {
		fmt.Printf("[*] Fetching: %s\n", targetURL)
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", 0, err
	}

	// Set headers
	req.Header.Set("User-Agent", hc.Config.UserAgent)
	if hc.Config.Cookie != "" {
		req.Header.Set("Cookie", hc.Config.Cookie)
	}
	for k, v := range hc.Config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := hc.Client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}

	if hc.Config.Verbose {
		fmt.Printf("[+] Status: %d, Size: %d bytes\n", resp.StatusCode, len(body))
	}

	return string(body), resp.StatusCode, nil
}

// ParseRawRequest parses raw HTTP request format
func ParseRawRequest(content string) (method, url, body string, headers map[string]string, err error) {
	headers = make(map[string]string)
	lines := strings.Split(content, "\n")

	if len(lines) < 1 {
		return "", "", "", headers, fmt.Errorf("invalid request format")
	}

	// Parse request line
	requestLine := strings.Fields(lines[0])
	if len(requestLine) < 3 {
		return "", "", "", headers, fmt.Errorf("invalid request line")
	}

	method = requestLine[0]
	path := requestLine[1]

	// Parse headers
	host := ""
	headersEnd := 0
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		// Empty line marks end of headers
		if line == "" {
			headersEnd = i
			break
		}

		// Parse header
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			headerName := strings.TrimSpace(parts[0])
			headerValue := strings.TrimSpace(parts[1])
			headers[headerName] = headerValue

			if strings.ToLower(headerName) == "host" {
				host = headerValue
			}
		}
	}

	// Construct full URL
	scheme := "https"
	if strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") {
		scheme = "http"
	}
	url = scheme + "://" + host + path

	// Get body
	if headersEnd < len(lines)-1 {
		body = strings.Join(lines[headersEnd+1:], "\n")
	}

	return method, url, body, headers, nil
}

// ReadURLList reads URLs from a file
func ReadURLList(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}

	return urls, scanner.Err()
}
