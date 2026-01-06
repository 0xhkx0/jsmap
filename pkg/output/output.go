package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0xhkx0/jsmap/pkg/types"
)

// ToTable converts findings to ASCII table format
func ToTable(findings *types.Findings) string {
	var output strings.Builder

	output.WriteString("\n")
	output.WriteString("╔═══════════════════════════════════════════════════════════════════╗\n")
	output.WriteString("║                         JS ANALYSIS RESULTS                       ║\n")
	output.WriteString("╚═══════════════════════════════════════════════════════════════════╝\n\n")

	// Endpoints
	if len(findings.Endpoints) > 0 {
		output.WriteString("📍 ENDPOINTS (" + fmt.Sprintf("%d", len(findings.Endpoints)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		endpoints := sortedKeys(findings.Endpoints)
		for _, ep := range endpoints {
			output.WriteString(fmt.Sprintf("  • %s\n", ep))
		}
		output.WriteString("\n")
	}

	// URLs
	if len(findings.URLs) > 0 {
		output.WriteString("🌐 URLs (" + fmt.Sprintf("%d", len(findings.URLs)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		urls := sortedKeys(findings.URLs)
		for _, url := range urls {
			output.WriteString(fmt.Sprintf("  • %s\n", url))
		}
		output.WriteString("\n")
	}

	// Secrets
	if len(findings.Secrets) > 0 {
		output.WriteString("🔐 SECRETS (" + fmt.Sprintf("%d", len(findings.Secrets)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		for _, secret := range findings.Secrets {
			output.WriteString(fmt.Sprintf("  ⚠️  %s\n", secret.Value))
		}
		output.WriteString("\n")
	}

	// Emails
	if len(findings.Emails) > 0 {
		output.WriteString("📧 EMAILS (" + fmt.Sprintf("%d", len(findings.Emails)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		emails := sortedKeys(findings.Emails)
		for _, email := range emails {
			output.WriteString(fmt.Sprintf("  • %s\n", email))
		}
		output.WriteString("\n")
	}

	// Files
	if len(findings.Files) > 0 {
		output.WriteString("📄 FILES (" + fmt.Sprintf("%d", len(findings.Files)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		files := sortedKeys(findings.Files)
		for _, file := range files {
			output.WriteString(fmt.Sprintf("  • %s\n", file))
		}
		output.WriteString("\n")
	}

	totalCount := len(findings.Endpoints) + len(findings.URLs) + len(findings.Secrets) + len(findings.Emails) + len(findings.Files)
	if totalCount == 0 {
		output.WriteString("No findings detected.\n\n")
	}

	output.WriteString("═══════════════════════════════════════════════════════════════════\n")

	return output.String()
}

// ToJSON converts findings to JSON format
func ToJSON(findings *types.Findings) string {
	data := map[string]interface{}{
		"endpoints": sortedKeys(findings.Endpoints),
		"urls":      sortedKeys(findings.URLs),
		"emails":    sortedKeys(findings.Emails),
		"files":     sortedKeys(findings.Files),
		"secrets":   findings.Secrets,
		"summary": map[string]int{
			"endpoints": len(findings.Endpoints),
			"urls":      len(findings.URLs),
			"secrets":   len(findings.Secrets),
			"emails":    len(findings.Emails),
			"files":     len(findings.Files),
			"total": len(findings.Endpoints) + len(findings.URLs) + len(findings.Secrets) + len(findings.Emails) + len(findings.Files),
		},
	}

	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	return string(jsonBytes)
}

// ToCSV converts findings to CSV format
func ToCSV(findings *types.Findings) string {
	var output strings.Builder
	w := csv.NewWriter(&output)

	// Header
	w.Write([]string{"Category", "Value", "Source"})

	// Endpoints
	for _, ep := range sortedKeys(findings.Endpoints) {
		w.Write([]string{"endpoint", ep, ""})
	}

	// URLs
	for _, url := range sortedKeys(findings.URLs) {
		w.Write([]string{"url", url, ""})
	}

	// Emails
	for _, email := range sortedKeys(findings.Emails) {
		w.Write([]string{"email", email, ""})
	}

	// Files
	for _, file := range sortedKeys(findings.Files) {
		w.Write([]string{"file", file, ""})
	}

	// Secrets
	for _, secret := range findings.Secrets {
		w.Write([]string{"secret", secret.Value, secret.Source})
	}

	w.Flush()
	return output.String()
}

// AggregatedToTable converts aggregated findings to ASCII table format
func AggregatedToTable(af *types.AggregatedFindings) string {
	var output strings.Builder

	output.WriteString("\n")
	output.WriteString("╔═══════════════════════════════════════════════════════════════════╗\n")
	output.WriteString("║              JSMAP - BUG BOUNTY JAVASCRIPT SCANNER               ║\n")
	output.WriteString("╚═══════════════════════════════════════════════════════════════════╝\n\n")

	// Source summary
	if len(af.Sources) > 0 {
		output.WriteString("📊 SOURCES (" + fmt.Sprintf("%d", len(af.Sources)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		sources := make([]string, 0, len(af.Sources))
		for s := range af.Sources {
			sources = append(sources, s)
		}
		sort.Strings(sources)
		for _, s := range sources {
			sf := af.Sources[s]
			output.WriteString(fmt.Sprintf("  • %s (Status: %d)\n", s, sf.StatusCode))
		}
		output.WriteString("\n")
	}

	// Endpoints
	if len(af.Endpoints) > 0 {
		output.WriteString("📍 API ENDPOINTS (" + fmt.Sprintf("%d", len(af.Endpoints)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		endpoints := make([]string, 0, len(af.Endpoints))
		for ep := range af.Endpoints {
			endpoints = append(endpoints, ep)
		}
		sort.Strings(endpoints)
		for _, ep := range endpoints {
			sources := af.Endpoints[ep]
			if len(sources) == 1 {
				output.WriteString(fmt.Sprintf("  • %s\n", ep))
			} else {
				output.WriteString(fmt.Sprintf("  • %s [%d sources]\n", ep, len(sources)))
			}
		}
		output.WriteString("\n")
	}

	// URLs
	if len(af.URLs) > 0 {
		output.WriteString("🌐 URLS (" + fmt.Sprintf("%d", len(af.URLs)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		urls := make([]string, 0, len(af.URLs))
		for u := range af.URLs {
			urls = append(urls, u)
		}
		sort.Strings(urls)
		for _, u := range urls {
			if len(u) > 60 {
				output.WriteString(fmt.Sprintf("  • %s...\n", u[:60]))
			} else {
				output.WriteString(fmt.Sprintf("  • %s\n", u))
			}
		}
		output.WriteString("\n")
	}

	// Secrets
	if len(af.Secrets) > 0 {
		output.WriteString("🔐 SECRETS (" + fmt.Sprintf("%d", len(af.Secrets)) + ") ⚠️  HIGH PRIORITY\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		for _, secret := range af.Secrets {
			output.WriteString(fmt.Sprintf("  ⚠️  %s\n", secret.Value))
			output.WriteString(fmt.Sprintf("      └─ Source: %s\n", secret.Source))
		}
		output.WriteString("\n")
	}

	// Emails
	if len(af.Emails) > 0 {
		output.WriteString("📧 EMAILS (" + fmt.Sprintf("%d", len(af.Emails)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		emails := make([]string, 0, len(af.Emails))
		for email := range af.Emails {
			emails = append(emails, email)
		}
		sort.Strings(emails)
		for _, email := range emails {
			output.WriteString(fmt.Sprintf("  • %s\n", email))
		}
		output.WriteString("\n")
	}

	// Files
	if len(af.Files) > 0 {
		output.WriteString("📄 FILES (" + fmt.Sprintf("%d", len(af.Files)) + ")\n")
		output.WriteString("────────────────────────────────────────────────────────────────\n")
		files := make([]string, 0, len(af.Files))
		for file := range af.Files {
			files = append(files, file)
		}
		sort.Strings(files)
		for _, file := range files {
			output.WriteString(fmt.Sprintf("  • %s\n", file))
		}
		output.WriteString("\n")
	}

	totalCount := len(af.Endpoints) + len(af.URLs) + len(af.Secrets) + len(af.Emails) + len(af.Files)
	if totalCount == 0 {
		output.WriteString("No findings detected.\n\n")
	}

	output.WriteString("═══════════════════════════════════════════════════════════════════\n")

	return output.String()
}

// AggregatedToJSON converts aggregated findings to JSON format
func AggregatedToJSON(af *types.AggregatedFindings) string {
	data := map[string]interface{}{
		"sources": func() []map[string]interface{} {
			var result []map[string]interface{}
			for _, src := range af.Sources {
				result = append(result, map[string]interface{}{
					"name":        src.Source,
					"url":         src.URL,
					"status_code": src.StatusCode,
				})
			}
			return result
		}(),
		"endpoints": func() map[string]interface{} {
			result := make(map[string]interface{})
			for ep, sources := range af.Endpoints {
				sourceNames := make([]string, len(sources))
				for i, src := range sources {
					sourceNames[i] = src.Source
				}
				result[ep] = map[string]interface{}{
					"count":   len(sources),
					"sources": sourceNames,
				}
			}
			return result
		}(),
		"urls": func() map[string]interface{} {
			result := make(map[string]interface{})
			for u, sources := range af.URLs {
				sourceNames := make([]string, len(sources))
				for i, src := range sources {
					sourceNames[i] = src.Source
				}
				result[u] = map[string]interface{}{
					"count":   len(sources),
					"sources": sourceNames,
				}
			}
			return result
		}(),
		"emails": func() map[string]interface{} {
			result := make(map[string]interface{})
			for email, sources := range af.Emails {
				sourceNames := make([]string, len(sources))
				for i, src := range sources {
					sourceNames[i] = src.Source
				}
				result[email] = map[string]interface{}{
					"count":   len(sources),
					"sources": sourceNames,
				}
			}
			return result
		}(),
		"files": func() map[string]interface{} {
			result := make(map[string]interface{})
			for file, sources := range af.Files {
				sourceNames := make([]string, len(sources))
				for i, src := range sources {
					sourceNames[i] = src.Source
				}
				result[file] = map[string]interface{}{
					"count":   len(sources),
					"sources": sourceNames,
				}
			}
			return result
		}(),
		"secrets": af.Secrets,
		"summary": map[string]interface{}{
			"endpoints": len(af.Endpoints),
			"urls":      len(af.URLs),
			"secrets":   len(af.Secrets),
			"emails":    len(af.Emails),
			"files":     len(af.Files),
			"total":     len(af.Endpoints) + len(af.URLs) + len(af.Secrets) + len(af.Emails) + len(af.Files),
			"sources":   len(af.Sources),
		},
	}

	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	return string(jsonBytes)
}

// AggregatedToCSV converts aggregated findings to CSV format
func AggregatedToCSV(af *types.AggregatedFindings) string {
	var output strings.Builder
	w := csv.NewWriter(&output)

	// Header
	w.Write([]string{"Category", "Value", "Sources", "Count"})

	// Endpoints
	endpoints := make([]string, 0, len(af.Endpoints))
	for ep := range af.Endpoints {
		endpoints = append(endpoints, ep)
	}
	sort.Strings(endpoints)
	for _, ep := range endpoints {
		sources := af.Endpoints[ep]
		sourceNames := make([]string, len(sources))
		for i, src := range sources {
			sourceNames[i] = src.Source
		}
		w.Write([]string{"endpoint", ep, strings.Join(sourceNames, ";"), fmt.Sprintf("%d", len(sources))})
	}

	// URLs
	urls := make([]string, 0, len(af.URLs))
	for u := range af.URLs {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	for _, u := range urls {
		sources := af.URLs[u]
		sourceNames := make([]string, len(sources))
		for i, src := range sources {
			sourceNames[i] = src.Source
		}
		w.Write([]string{"url", u, strings.Join(sourceNames, ";"), fmt.Sprintf("%d", len(sources))})
	}

	// Emails
	emails := make([]string, 0, len(af.Emails))
	for email := range af.Emails {
		emails = append(emails, email)
	}
	sort.Strings(emails)
	for _, email := range emails {
		sources := af.Emails[email]
		sourceNames := make([]string, len(sources))
		for i, src := range sources {
			sourceNames[i] = src.Source
		}
		w.Write([]string{"email", email, strings.Join(sourceNames, ";"), fmt.Sprintf("%d", len(sources))})
	}

	// Files
	files := make([]string, 0, len(af.Files))
	for file := range af.Files {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		sources := af.Files[file]
		sourceNames := make([]string, len(sources))
		for i, src := range sources {
			sourceNames[i] = src.Source
		}
		w.Write([]string{"file", file, strings.Join(sourceNames, ";"), fmt.Sprintf("%d", len(sources))})
	}

	// Secrets
	for _, secret := range af.Secrets {
		w.Write([]string{"secret", secret.Value, secret.Source, "1"})
	}

	w.Flush()
	return output.String()
}

// AggregatedToHTML converts aggregated findings to HTML format
func AggregatedToHTML(af *types.AggregatedFindings) string {
	var output strings.Builder

	output.WriteString(`<!DOCTYPE html>
<html>
<head>
    <title>jsmap - Bug Bounty Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }
        h2 { color: #0066cc; margin-top: 30px; }
        .high { color: #d32f2f; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; font-weight: bold; }
        tr:hover { background: #f9f9f9; }
        .endpoint { color: #1976d2; }
        .secret { color: #d32f2f; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 20px 0; }
        .stat-box { background: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #0066cc; }
        .stat-label { color: #666; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 jsmap - Bug Bounty JavaScript Scanner Report</h1>
`)

	totalCount := len(af.Endpoints) + len(af.URLs) + len(af.Secrets) + len(af.Emails) + len(af.Files)
	
	// Summary statistics
	output.WriteString(`<div class="summary">`)
	output.WriteString(fmt.Sprintf(`<div class="stat-box"><div class="stat-number">%d</div><div class="stat-label">Endpoints</div></div>`, len(af.Endpoints)))
	output.WriteString(fmt.Sprintf(`<div class="stat-box"><div class="stat-number">%d</div><div class="stat-label">URLs</div></div>`, len(af.URLs)))
	output.WriteString(fmt.Sprintf(`<div class="stat-box"><div class="stat-number"><span class="high">%d</span></div><div class="stat-label">Secrets</div></div>`, len(af.Secrets)))
	output.WriteString(fmt.Sprintf(`<div class="stat-box"><div class="stat-number">%d</div><div class="stat-label">Emails</div></div>`, len(af.Emails)))
	output.WriteString(fmt.Sprintf(`<div class="stat-box"><div class="stat-number">%d</div><div class="stat-label">Files</div></div>`, len(af.Files)))
	output.WriteString(`</div>`)

	// Sources
	if len(af.Sources) > 0 {
		output.WriteString(`<h2>📊 Sources</h2><table><tr><th>Source</th><th>URL</th><th>Status</th></tr>`)
		sources := make([]string, 0, len(af.Sources))
		for s := range af.Sources {
			sources = append(sources, s)
		}
		sort.Strings(sources)
		for _, s := range sources {
			sf := af.Sources[s]
			output.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%d</td></tr>`, sf.Source, sf.URL, sf.StatusCode))
		}
		output.WriteString(`</table>`)
	}

	// Secrets
	if len(af.Secrets) > 0 {
		output.WriteString(`<h2 class="high">🔐 Secrets (HIGH PRIORITY)</h2><table><tr><th>Secret</th><th>Type</th><th>Source</th></tr>`)
		for _, secret := range af.Secrets {
			output.WriteString(fmt.Sprintf(`<tr><td class="high">%s</td><td>%s</td><td>%s</td></tr>`, secret.Value, secret.Type, secret.Source))
		}
		output.WriteString(`</table>`)
	}

	// Endpoints
	if len(af.Endpoints) > 0 {
		output.WriteString(`<h2>📍 API Endpoints</h2><table><tr><th>Endpoint</th><th>Sources</th><th>Count</th></tr>`)
		endpoints := make([]string, 0, len(af.Endpoints))
		for ep := range af.Endpoints {
			endpoints = append(endpoints, ep)
		}
		sort.Strings(endpoints)
		for _, ep := range endpoints {
			sources := af.Endpoints[ep]
			sourceNames := make([]string, len(sources))
			for i, src := range sources {
				sourceNames[i] = src.Source
			}
			output.WriteString(fmt.Sprintf(`<tr><td class="endpoint">%s</td><td>%s</td><td>%d</td></tr>`, ep, strings.Join(sourceNames, ", "), len(sources)))
		}
		output.WriteString(`</table>`)
	}

	// URLs
	if len(af.URLs) > 0 {
		output.WriteString(`<h2>🌐 URLs</h2><table><tr><th>URL</th><th>Sources</th></tr>`)
		urls := make([]string, 0, len(af.URLs))
		for u := range af.URLs {
			urls = append(urls, u)
		}
		sort.Strings(urls)
		for _, u := range urls {
			sources := af.URLs[u]
			sourceNames := make([]string, len(sources))
			for i, src := range sources {
				sourceNames[i] = src.Source
			}
			output.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td></tr>`, u, strings.Join(sourceNames, ", ")))
		}
		output.WriteString(`</table>`)
	}

	// Emails
	if len(af.Emails) > 0 {
		output.WriteString(`<h2>📧 Emails</h2><table><tr><th>Email</th><th>Sources</th></tr>`)
		emails := make([]string, 0, len(af.Emails))
		for email := range af.Emails {
			emails = append(emails, email)
		}
		sort.Strings(emails)
		for _, email := range emails {
			sources := af.Emails[email]
			sourceNames := make([]string, len(sources))
			for i, src := range sources {
				sourceNames[i] = src.Source
			}
			output.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td></tr>`, email, strings.Join(sourceNames, ", ")))
		}
		output.WriteString(`</table>`)
	}

	// Files
	if len(af.Files) > 0 {
		output.WriteString(`<h2>📄 Files</h2><table><tr><th>File</th><th>Sources</th></tr>`)
		files := make([]string, 0, len(af.Files))
		for file := range af.Files {
			files = append(files, file)
		}
		sort.Strings(files)
		for _, file := range files {
			sources := af.Files[file]
			sourceNames := make([]string, len(sources))
			for i, src := range sources {
				sourceNames[i] = src.Source
			}
			output.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td></tr>`, file, strings.Join(sourceNames, ", ")))
		}
		output.WriteString(`</table>`)
	}

	if totalCount == 0 {
		output.WriteString(`<div class="section"><p>No findings detected.</p></div>`)
	}

	output.WriteString(`</div></body></html>`)

	return output.String()
}

// Helper function to get sorted keys from map
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
