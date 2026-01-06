package types

// Finding represents a single finding
type Finding struct {
	Category string `json:"category"`
	Value    string `json:"value"`
	Source   string `json:"source"`
}

// Findings holds all categorized findings
type Findings struct {
	Endpoints map[string]bool
	URLs      map[string]bool
	Secrets   []Finding
	Emails    map[string]bool
	Files     map[string]bool
	SeenKeys  map[string]bool
	Verbose   bool
}

// SourceFinding tracks findings from a specific source
type SourceFinding struct {
	Source     string
	URL        string
	StatusCode int
	Count      int
}

// SecretFinding includes source information
type SecretFinding struct {
	Value      string
	Type       string
	Source     string
	URL        string
	StatusCode int
}

// AggregatedFindings holds findings across multiple sources
type AggregatedFindings struct {
	Endpoints map[string][]SourceFinding
	URLs      map[string][]SourceFinding
	Secrets   []SecretFinding
	Emails    map[string][]SourceFinding
	Files     map[string][]SourceFinding
	Sources   map[string]SourceFinding
	SeenKeys  map[string]bool
	Verbose   bool
}

// NewFindings creates a new Findings instance
func NewFindings(verbose bool) *Findings {
	return &Findings{
		Endpoints: make(map[string]bool),
		URLs:      make(map[string]bool),
		Secrets:   []Finding{},
		Emails:    make(map[string]bool),
		Files:     make(map[string]bool),
		SeenKeys:  make(map[string]bool),
		Verbose:   verbose,
	}
}

// NewAggregatedFindings creates a new aggregated findings instance
func NewAggregatedFindings() *AggregatedFindings {
	return &AggregatedFindings{
		Endpoints: make(map[string][]SourceFinding),
		URLs:      make(map[string][]SourceFinding),
		Secrets:   []SecretFinding{},
		Emails:    make(map[string][]SourceFinding),
		Files:     make(map[string][]SourceFinding),
		Sources:   make(map[string]SourceFinding),
		SeenKeys:  make(map[string]bool),
		Verbose:   false,
	}
}

// AddFindings adds findings from a source
func (af *AggregatedFindings) AddFindings(findings *Findings, source, url string, statusCode int) {
	// Track source
	if _, exists := af.Sources[source]; !exists {
		af.Sources[source] = SourceFinding{
			Source:     source,
			URL:        url,
			StatusCode: statusCode,
			Count:      0,
		}
	}

	// Add endpoints
	for endpoint := range findings.Endpoints {
		key := "ep:" + endpoint
		if !af.SeenKeys[key] {
			af.SeenKeys[key] = true
			af.Endpoints[endpoint] = append(af.Endpoints[endpoint], SourceFinding{
				Source:     source,
				URL:        url,
				StatusCode: statusCode,
			})
		}
	}

	// Add URLs
	for u := range findings.URLs {
		key := "url:" + u
		if !af.SeenKeys[key] {
			af.SeenKeys[key] = true
			af.URLs[u] = append(af.URLs[u], SourceFinding{
				Source:     source,
				URL:        url,
				StatusCode: statusCode,
			})
		}
	}

	// Add secrets
	for _, secret := range findings.Secrets {
		key := "sec:" + secret.Value
		if !af.SeenKeys[key] {
			af.SeenKeys[key] = true
			af.Secrets = append(af.Secrets, SecretFinding{
				Value:      secret.Value,
				Type:       secret.Category,
				Source:     source,
				URL:        url,
				StatusCode: statusCode,
			})
		}
	}

	// Add emails
	for email := range findings.Emails {
		key := "email:" + email
		if !af.SeenKeys[key] {
			af.SeenKeys[key] = true
			af.Emails[email] = append(af.Emails[email], SourceFinding{
				Source:     source,
				URL:        url,
				StatusCode: statusCode,
			})
		}
	}

	// Add files
	for file := range findings.Files {
		key := "file:" + file
		if !af.SeenKeys[key] {
			af.SeenKeys[key] = true
			af.Files[file] = append(af.Files[file], SourceFinding{
				Source:     source,
				URL:        url,
				StatusCode: statusCode,
			})
		}
	}
}
