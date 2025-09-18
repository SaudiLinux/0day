package scanner

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AIDetector provides AI-powered vulnerability detection
type AIDetector struct {
	enabled              bool
	confidenceThreshold float64
	trainingDataDays    int
	patterns            []AIPattern
	mu                  sync.RWMutex
	stats               *AIStats
}

// AIPattern represents a learned vulnerability pattern
type AIPattern struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Pattern      string    `json:"pattern"`
	regex        *regexp.Regexp
	ServiceType  string    `json:"service_type"`
	Severity     string    `json:"severity"`
	Confidence   float64   `json:"confidence"`
	LastSeen     time.Time `json:"last_seen"`
	MatchCount   int       `json:"match_count"`
	FalsePositives int     `json:"false_positives"`
	Description  string    `json:"description"`
	CVE          string    `json:"cve,omitempty"`
	CVSS         float64   `json:"cvss,omitempty"`
}

// AIStats tracks AI detector statistics
type AIStats struct {
	TotalScans      int64     `json:"total_scans"`
	PatternsFound   int64     `json:"patterns_found"`
	FalsePositives  int64     `json:"false_positives"`
	LastUpdated     time.Time `json:"last_updated"`
	LearningRate    float64   `json:"learning_rate"`
}

// AIConfig holds AI detection configuration
type AIConfig struct {
	Enabled             bool    `yaml:"enabled" json:"enabled"`
	ConfidenceThreshold float64 `yaml:"confidence_threshold" json:"confidence_threshold"`
	TrainingDataDays    int     `yaml:"training_data_days" json:"training_data_days"`
}

// NewAIDetector creates a new AI-powered vulnerability detector
func NewAIDetector(config AIConfig) *AIDetector {
	detector := &AIDetector{
		enabled:              config.Enabled,
		confidenceThreshold: config.ConfidenceThreshold,
		trainingDataDays:    config.TrainingDataDays,
		patterns:            []AIPattern{},
		stats: &AIStats{
			LearningRate: 0.1,
			LastUpdated:  time.Now(),
		},
	}
	
	// Initialize with default patterns
	detector.initializePatterns()
	return detector
}

// AnalyzeService performs AI analysis on service information
func (ai *AIDetector) AnalyzeService(service Service, target Target) []Vulnerability {
	if !ai.enabled {
		return nil
	}
	
	ai.mu.RLock()
	defer ai.mu.RUnlock()
	
	var vulns []Vulnerability
	
	// Analyze service banner for unusual patterns
	if service.Banner != "" {
		bannerVulns := ai.analyzeBanner(service.Banner, service, target)
		vulns = append(vulns, bannerVulns...)
	}
	
	// Analyze service version for known vulnerable patterns
	if service.Version != "" && service.Version != "unknown" {
		versionVulns := ai.analyzeVersion(service.Version, service, target)
		vulns = append(vulns, versionVulns...)
	}
	
	// Analyze service name and protocol for anomalies
	nameVulns := ai.analyzeServiceName(service.Name, service.Protocol, target)
	vulns = append(vulns, nameVulns...)
	
	// Analyze port number for known vulnerable services
	portVulns := ai.analyzePort(service.Port, service.Name)
	vulns = append(vulns, portVulns...)
	
	// Update statistics
	ai.updateStats(len(vulns))
	
	return vulns
}

// analyzePort analyzes port numbers for known vulnerable services
func (ai *AIDetector) analyzePort(port int, serviceName string) []Vulnerability {
	var vulns []Vulnerability
	
	// Known vulnerable ports and services
	vulnerablePorts := map[int][]Vulnerability{
		23: {{
			ID:          "TELNET_UNENCRYPTED",
			Name:        "Telnet Unencrypted Protocol",
			Description: "Telnet protocol transmits data in plaintext, allowing credential interception",
			Severity:    "High",
			CVE:         "N/A",
		}},
		135: {{
			ID:          "RPC_ENDPOINT_MAPPER",
			Name:        "Windows RPC Endpoint Mapper",
			Description: "RPC service can be exploited for remote code execution",
			Severity:    "Critical",
			CVE:         "MS03-026",
		}},
		139: {{
			ID:          "NETBIOS_SMB",
			Name:        "NetBIOS SMB Service",
			Description: "SMB service vulnerable to various exploits including EternalBlue",
			Severity:    "Critical",
			CVE:         "MS17-010",
		}},
		445: {{
			ID:          "SMB_DIRECT_HOST",
			Name:        "SMB Direct Host",
			Description: "SMB service vulnerable to remote code execution exploits",
			Severity:    "Critical",
			CVE:         "MS17-010",
		}},
		1433: {{
			ID:          "MSSQL_DATABASE",
			Name:        "Microsoft SQL Server",
			Description: "Database service potentially vulnerable to SQL injection and buffer overflows",
			Severity:    "High",
			CVE:         "MS02-039",
		}},
		3306: {{
			ID:          "MYSQL_DATABASE",
			Name:        "MySQL Database",
			Description: "Database service potentially vulnerable to authentication bypass",
			Severity:    "Medium",
			CVE:         "CVE-2012-2122",
		}},
	}
	
	// Check if port is known vulnerable
	if portVulns, exists := vulnerablePorts[port]; exists {
		// Verify service name matches expected service for this port
		expectedServices := map[int]string{
			23:   "telnet",
			135:  "msrpc",
			139:  "netbios",
			445:  "microsoft-ds",
			1433: "ms-sql",
			3306: "mysql",
		}
		
		expectedService := expectedServices[port]
		if strings.Contains(strings.ToLower(serviceName), expectedService) {
			vulns = append(vulns, portVulns...)
		}
	}
	
	return vulns
}

// analyzeBanner analyzes service banners for suspicious patterns
func (ai *AIDetector) analyzeBanner(banner string, service Service, target Target) []Vulnerability {
	var vulns []Vulnerability
	bannerLower := strings.ToLower(banner)
	
	for _, pattern := range ai.patterns {
		if pattern.ServiceType != "" && pattern.ServiceType != service.Name {
			continue
		}
		
		if pattern.regex == nil {
			continue
		}
		
		if pattern.regex.MatchString(bannerLower) {
			// Calculate confidence based on pattern history
			confidence := ai.calculateConfidence(pattern)
			
			if confidence >= ai.confidenceThreshold {
				vuln := Vulnerability{
					ID:          fmt.Sprintf("AI-%s", pattern.ID),
					Name:        fmt.Sprintf("AI Detected: %s", pattern.Name),
					Severity:    ai.adjustSeverity(pattern.Severity, confidence),
					Description: fmt.Sprintf("AI pattern detected: %s (confidence: %.2f)", pattern.Description, confidence),
					CVE:         pattern.CVE,
					CVSS:        ai.adjustCVSS(pattern.CVSS, confidence),
					Proof:       fmt.Sprintf("Banner analysis: %.2f%% confidence match for pattern '%s'", confidence*100, pattern.Name),
				}
				vulns = append(vulns, vuln)
				
				// Update pattern statistics
				ai.updatePatternStats(pattern.ID, true)
			}
		}
	}
	
	// Additional heuristic analysis
	heuristicVulns := ai.heuristicBannerAnalysis(banner, service, target)
	vulns = append(vulns, heuristicVulns...)
	
	return vulns
}

// analyzeVersion analyzes version strings for suspicious patterns
func (ai *AIDetector) analyzeVersion(version string, service Service, target Target) []Vulnerability {
	var vulns []Vulnerability
	
	// Check for suspicious version patterns
	suspiciousPatterns := []struct {
		pattern     string
		description string
		severity    string
	}{
		{`^\d+\.\d+\.\d+$`, "Standard version format", "Info"},
		{`^\d+\.\d+$`, "Short version format", "Info"},
		{`.*beta.*`, "Beta version detected", "Low"},
		{`.*alpha.*`, "Alpha version detected", "Medium"},
		{`.*dev.*`, "Development version detected", "Medium"},
		{`.*rc\d+.*`, "Release candidate detected", "Low"},
		{`\d+\.\d+\.\d+.*\.(\d+)$`, "Extended version format", "Info"},
	}
	
	for _, suspicious := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(suspicious.pattern, strings.ToLower(version)); matched {
			confidence := 0.6 // Base confidence for version patterns
			
			vuln := Vulnerability{
				ID:          fmt.Sprintf("AI-VERSION-%s", strings.ToUpper(strings.ReplaceAll(suspicious.description, " ", "_"))),
				Name:        fmt.Sprintf("Version Pattern: %s", suspicious.description),
				Severity:    suspicious.severity,
				Description: fmt.Sprintf("Version string '%s' matches pattern: %s", version, suspicious.description),
				CVE:         "",
				CVSS:        ai.severityToCVSS(suspicious.severity) * confidence,
				Proof:       fmt.Sprintf("Version analysis: '%s' detected", version),
			}
			vulns = append(vulns, vuln)
		}
	}
	
	return vulns
}

// analyzeServiceName analyzes service names and protocols for anomalies
func (ai *AIDetector) analyzeServiceName(name, protocol string, target Target) []Vulnerability {
	var vulns []Vulnerability
	
	// Check for unusual service/protocol combinations
	unusualCombinations := []struct {
		service   string
		protocol  string
		description string
		severity  string
	}{
		{"http", "udp", "HTTP over UDP is unusual", "Medium"},
		{"ftp", "udp", "FTP over UDP is suspicious", "High"},
		{"ssh", "udp", "SSH over UDP is anomalous", "High"},
		{"telnet", "udp", "Telnet over UDP is unusual", "Medium"},
	}
	
	for _, unusual := range unusualCombinations {
		if strings.ToLower(name) == unusual.service && strings.ToLower(protocol) == unusual.protocol {
			vuln := Vulnerability{
				ID:          fmt.Sprintf("AI-PROTO-%s-%s", strings.ToUpper(unusual.service), strings.ToUpper(unusual.protocol)),
				Name:        fmt.Sprintf("Unusual Protocol: %s", unusual.description),
				Severity:    unusual.severity,
				Description: fmt.Sprintf("Service '%s' detected over protocol '%s': %s", name, protocol, unusual.description),
				CVE:         "",
				CVSS:        ai.severityToCVSS(unusual.severity) * 0.8,
				Proof:       fmt.Sprintf("Service/Protocol anomaly: %s/%s", name, protocol),
			}
			vulns = append(vulns, vuln)
		}
	}
	
	return vulns
}

// heuristicBannerAnalysis performs additional heuristic analysis on banners
func (ai *AIDetector) heuristicBannerAnalysis(banner string, service Service, target Target) []Vulnerability {
	var vulns []Vulnerability
	
	// Check for default credentials hints
	defaultCreds := []string{"default", "admin", "password", "123456", "root", "guest"}
	for _, cred := range defaultCreds {
		if strings.Contains(strings.ToLower(banner), cred) {
			vuln := Vulnerability{
				ID:          "AI-DEFAULT-CREDS",
				Name:        "Potential Default Credentials",
				Severity:    "High",
				Description: fmt.Sprintf("Banner contains potential default credential reference: '%s'", cred),
				CVE:         "",
				CVSS:        7.5,
				Proof:       fmt.Sprintf("Default credential hint found: '%s'", cred),
			}
			vulns = append(vulns, vuln)
			break
		}
	}
	
	// Check for error messages that might reveal system information
	errorPatterns := []string{"error", "exception", "failed", "denied", "unauthorized"}
	errorCount := 0
	for _, pattern := range errorPatterns {
		if strings.Contains(strings.ToLower(banner), pattern) {
			errorCount++
		}
	}
	
	if errorCount >= 3 {
		vuln := Vulnerability{
			ID:          "AI-ERROR-LEAK",
			Name:        "Information Disclosure via Error Messages",
			Severity:    "Medium",
			Description: "Banner contains multiple error-related keywords that may indicate information leakage",
			CVE:         "",
			CVSS:        5.0,
			Proof:       fmt.Sprintf("Multiple error indicators found (%d)", errorCount),
		}
		vulns = append(vulns, vuln)
	}
	
	return vulns
}

// calculateConfidence calculates confidence score for a pattern
func (ai *AIDetector) calculateConfidence(pattern AIPattern) float64 {
	baseConfidence := pattern.Confidence
	
	// Adjust based on match history
	if pattern.MatchCount > 0 {
		// Reduce confidence if high false positive rate
		falsePositiveRate := float64(pattern.FalsePositives) / float64(pattern.MatchCount)
		if falsePositiveRate > 0.3 {
			baseConfidence *= 0.5
		} else if falsePositiveRate > 0.1 {
			baseConfidence *= 0.8
		}
	}
	
	// Adjust based on recency
	daysSinceLastSeen := time.Since(pattern.LastSeen).Hours() / 24
	if daysSinceLastSeen > float64(ai.trainingDataDays) {
		baseConfidence *= 0.7 // Reduce confidence for old patterns
	}
	
	return math.Min(baseConfidence, 1.0)
}

// adjustSeverity adjusts severity based on confidence
func (ai *AIDetector) adjustSeverity(baseSeverity string, confidence float64) string {
	severityLevels := map[string]int{
		"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5,
	}
	
	baseLevel := severityLevels[baseSeverity]
	if confidence > 0.9 {
		return baseSeverity // Keep original severity for high confidence
	} else if confidence > 0.7 {
		return baseSeverity // Keep original severity for good confidence
	} else if confidence > 0.5 {
		// Reduce severity by one level for medium confidence
		if baseLevel > 1 {
			baseLevel--
		}
	} else {
		// Reduce severity by two levels for low confidence
		if baseLevel > 2 {
			baseLevel -= 2
		} else {
			baseLevel = 1
		}
	}
	
	// Convert back to severity string
	for sev, level := range severityLevels {
		if level == baseLevel {
			return sev
		}
	}
	
	return "Info"
}

// adjustCVSS adjusts CVSS score based on confidence
func (ai *AIDetector) adjustCVSS(baseCVSS, confidence float64) float64 {
	if baseCVSS == 0 {
		return 0
	}
	return baseCVSS * confidence
}

// severityToCVSS converts severity to approximate CVSS score
func (ai *AIDetector) severityToCVSS(severity string) float64 {
	severityMap := map[string]float64{
		"Info":   0.0,
		"Low":    3.0,
		"Medium": 5.0,
		"High":   7.5,
		"Critical": 9.0,
	}
	
	if cvss, exists := severityMap[severity]; exists {
		return cvss
	}
	
	return 5.0 // Default to medium
}

// updateStats updates AI detector statistics
func (ai *AIDetector) updateStats(vulnerabilitiesFound int) {
	ai.stats.TotalScans++
	ai.stats.PatternsFound += int64(vulnerabilitiesFound)
	ai.stats.LastUpdated = time.Now()
}

// updatePatternStats updates statistics for a specific pattern
func (ai *AIDetector) updatePatternStats(patternID string, matchFound bool) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	
	for i := range ai.patterns {
		if ai.patterns[i].ID == patternID {
			if matchFound {
				ai.patterns[i].MatchCount++
				ai.patterns[i].LastSeen = time.Now()
			}
			break
		}
	}
}

// initializePatterns sets up initial AI detection patterns
func (ai *AIDetector) initializePatterns() {
	ai.patterns = []AIPattern{
		{
			ID:          "AI-001",
			Name:        "Suspicious SSH Banner",
			Pattern:     `(?i)(ssh.*version|openssh.*[0-9]+\.[0-9]+).*?(vulnerable|exploit|hack)`,
			ServiceType: "ssh",
			Severity:    "High",
			Confidence:  0.8,
			Description: "SSH banner contains suspicious keywords",
			CVE:         "",
			CVSS:        7.0,
		},
		{
			ID:          "AI-002",
			Name:        "Development Server Detection",
			Pattern:     `(?i)(development|dev|test|staging|localhost|127\.0\.0\.1)`,
			ServiceType: "",
			Severity:    "Medium",
			Confidence:  0.7,
			Description: "Development or test server detected in production",
			CVE:         "",
			CVSS:        5.0,
		},
		{
			ID:          "AI-003",
			Name:        "Default Service Detection",
			Pattern:     `(?i)(default|initial|setup|install|configure)`,
			ServiceType: "",
			Severity:    "Low",
			Confidence:  0.6,
			Description: "Service appears to be in default configuration",
			CVE:         "",
			CVSS:        3.0,
		},
		{
			ID:          "AI-004",
			Name:        "Information Disclosure Pattern",
			Pattern:     `(?i)(error|exception|debug|trace|stack|internal|private)`,
			ServiceType: "",
			Severity:    "Medium",
			Confidence:  0.75,
			Description: "Potential information disclosure in service response",
			CVE:         "",
			CVSS:        5.5,
		},
		{
			ID:          "AI-005",
			Name:        "Weak SSL/TLS Configuration",
			Pattern:     `(?i)(ssl.*v\d|tls.*1\.[0-1]|cipher.*null|encryption.*none)`,
			ServiceType: "https",
			Severity:    "High",
			Confidence:  0.85,
			Description: "Weak SSL/TLS configuration detected",
			CVE:         "",
			CVSS:        7.5,
		},
	}
	
	// Compile regex patterns
	for i := range ai.patterns {
		ai.patterns[i].regex = regexp.MustCompile(ai.patterns[i].Pattern)
		ai.patterns[i].LastSeen = time.Now()
	}
}

// GetStats returns AI detector statistics
func (ai *AIDetector) GetStats() AIStats {
	return *ai.stats
}

// SetEnabled enables or disables AI detection
func (ai *AIDetector) SetEnabled(enabled bool) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	ai.enabled = enabled
}

// IsEnabled returns whether AI detection is enabled
func (ai *AIDetector) IsEnabled() bool {
	ai.mu.RLock()
	defer ai.mu.RUnlock()
	return ai.enabled
}

// ReportFalsePositive reports a false positive to improve AI accuracy
func (ai *AIDetector) ReportFalsePositive(vulnerabilityID string) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	
	ai.stats.FalsePositives++
	
	// Extract pattern ID from vulnerability ID
	if strings.HasPrefix(vulnerabilityID, "AI-") {
		parts := strings.Split(vulnerabilityID, "-")
		if len(parts) >= 2 {
			patternID := parts[1]
			for i := range ai.patterns {
				if ai.patterns[i].ID == patternID {
					ai.patterns[i].FalsePositives++
					break
				}
			}
		}
	}
}

// ExportPatterns exports learned patterns for backup or sharing
func (ai *AIDetector) ExportPatterns() ([]byte, error) {
	ai.mu.RLock()
	defer ai.mu.RUnlock()
	
	return json.MarshalIndent(ai.patterns, "", "  ")
}

// ImportPatterns imports learned patterns
func (ai *AIDetector) ImportPatterns(data []byte) error {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	
	var patterns []AIPattern
	if err := json.Unmarshal(data, &patterns); err != nil {
		return err
	}
	
	// Compile regex patterns
	for i := range patterns {
		patterns[i].regex = regexp.MustCompile(patterns[i].Pattern)
	}
	
	ai.patterns = patterns
	return nil
}