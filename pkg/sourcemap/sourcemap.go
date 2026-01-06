package sourcemap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// SourceMap represents a JavaScript source map
type SourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
	Names          []string `json:"names"`
	Mappings       string   `json:"mappings"`
	File           string   `json:"file"`
}

// FetchSourceMap attempts to fetch the source map for a JS file
func FetchSourceMap(jsURL string, httpClient *http.Client, verbose bool) (*SourceMap, error) {
	// Try common source map URL patterns
	mapURLs := []string{}
	
	// Pattern 1: file.js -> file.js.map
	if strings.HasSuffix(jsURL, ".js") {
		mapURLs = append(mapURLs, jsURL+".map")
	}
	
	// Pattern 2: file.js?query -> file.js.map
	if strings.Contains(jsURL, ".js?") {
		parts := strings.Split(jsURL, "?")
		mapURLs = append(mapURLs, parts[0]+".map")
	}

	for _, mapURL := range mapURLs {
		if verbose {
			fmt.Printf("[*] Trying source map: %s\n", mapURL)
		}

		req, err := http.NewRequest("GET", mapURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		var sourceMap SourceMap
		if err := json.NewDecoder(resp.Body).Decode(&sourceMap); err != nil {
			continue
		}

		// Validate it's actually a source map
		if sourceMap.Version > 0 && len(sourceMap.Sources) > 0 {
			if verbose {
				fmt.Printf("[+] Found source map with %d source files\n", len(sourceMap.Sources))
			}
			return &sourceMap, nil
		}
	}

	return nil, fmt.Errorf("no valid source map found")
}

// ExtractOriginalSource combines all source files from a source map
func ExtractOriginalSource(sourceMap *SourceMap) string {
	if len(sourceMap.SourcesContent) == 0 {
		return ""
	}

	var combined strings.Builder
	for i, content := range sourceMap.SourcesContent {
		if content == "" {
			continue
		}

		// Add file separator comment
		if i < len(sourceMap.Sources) {
			combined.WriteString(fmt.Sprintf("\n\n// ========== SOURCE: %s ==========\n\n", sourceMap.Sources[i]))
		}
		
		combined.WriteString(content)
	}

	return combined.String()
}
