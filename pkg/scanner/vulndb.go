package scanner

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// VulnDatabase manages vulnerability data and matching
type VulnDatabase struct {
	mu              sync.RWMutex
	serviceVulns    map[string][]Vulnerability
	bannerPatterns  []BannerPattern
}

// BannerPattern represents a vulnerability pattern in service banners
type BannerPattern struct {
	Pattern     *regexp.Regexp
	Service     string
	VulnName    string
	Description string
	Severity    string
	CVE         string
	CVSS        float64
}

// NewVulnDatabase creates a new vulnerability database with built-in vulnerability data
func NewVulnDatabase() *VulnDatabase {
	vdb := &VulnDatabase{
		serviceVulns:   make(map[string][]Vulnerability),
		bannerPatterns: []BannerPattern{},
	}
	
	// Initialize with common vulnerability data
	vdb.initializeVulnerabilityData()
	return vdb
}

// CheckService checks for vulnerabilities in a specific service and version
func (v *VulnDatabase) CheckService(serviceName, serviceVersion string) []Vulnerability {
	v.mu.RLock()
	defer v.mu.RUnlock()
	
	var vulns []Vulnerability
	serviceName = strings.ToLower(serviceName)
	
	// Check for service-specific vulnerabilities
	if serviceVulns, exists := v.serviceVulns[serviceName]; exists {
		for _, vuln := range serviceVulns {
			if strings.EqualFold(vuln.ID, serviceVersion) || strings.Contains(vuln.Description, serviceVersion) {
				vulns = append(vulns, vuln)
			}
		}
	}
	
	return vulns
}

// isVersionAffected checks if a version is affected by a vulnerability
func (v *VulnDatabase) isVersionAffected(version string, affectedVersions []string) bool {
	if len(affectedVersions) == 0 {
		return true // No version specified means all versions are affected
	}
	
	version = strings.TrimSpace(strings.ToLower(version))
	
	for _, affected := range affectedVersions {
		affected = strings.TrimSpace(strings.ToLower(affected))
		
		// Exact match
		if affected == version {
			return true
		}
		
		// Version range (e.g., ">=1.0.0", "<2.0.0")
		if strings.HasPrefix(affected, ">=") {
			minVersion := strings.TrimPrefix(affected, ">=")
			if v.compareVersions(version, minVersion) >= 0 {
				return true
			}
		} else if strings.HasPrefix(affected, "<=") {
			maxVersion := strings.TrimPrefix(affected, "<=")
			if v.compareVersions(version, maxVersion) <= 0 {
				return true
			}
		} else if strings.HasPrefix(affected, "<") {
			maxVersion := strings.TrimPrefix(affected, "<")
			if v.compareVersions(version, maxVersion) < 0 {
				return true
			}
		} else if strings.HasPrefix(affected, ">") {
			minVersion := strings.TrimPrefix(affected, ">")
			if v.compareVersions(version, minVersion) > 0 {
				return true
			}
		}
	}
	
	return false
}

// compareVersions compares two version strings (simplified)
func (v *VulnDatabase) compareVersions(v1, v2 string) int {
	// Simple version comparison - can be enhanced
	if v1 == v2 {
		return 0
	}
	
	// Extract numeric parts
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")
	
	for i := 0; i < len(v1Parts) && i < len(v2Parts); i++ {
		v1Num, err1 := strconv.Atoi(v1Parts[i])
		v2Num, err2 := strconv.Atoi(v2Parts[i])
		
		if err1 == nil && err2 == nil {
			if v1Num < v2Num {
				return -1
			} else if v1Num > v2Num {
				return 1
			}
		}
	}
	
	return 0
}

// CheckBanner checks for vulnerabilities based on service banner content
func (v *VulnDatabase) CheckBanner(banner string) []Vulnerability {
	v.mu.RLock()
	defer v.mu.RUnlock()
	
	var vulns []Vulnerability
	banner = strings.ToLower(banner)
	
	for _, pattern := range v.bannerPatterns {
		if pattern.Pattern.MatchString(banner) {
			vulns = append(vulns, Vulnerability{
				ID:          generateVulnID(pattern.Service, pattern.VulnName),
				Name:        pattern.VulnName,
				Severity:    pattern.Severity,
				Description: pattern.Description,
				CVE:         pattern.CVE,
				CVSS:        pattern.CVSS,
				Proof:       "Banner pattern match: " + banner,
			})
		}
	}
	
	return vulns
}

// versionMatches checks if a version is affected by a vulnerability
func (v *VulnDatabase) versionMatches(vuln Vulnerability, version string) bool {
	if version == "" || version == "unknown" {
		return false
	}
	
	// Simple version matching - can be enhanced with proper version comparison
	// For now, we'll do a basic contains check
	return strings.Contains(version, vuln.ID) || strings.Contains(vuln.Description, version)
}

// initializeVulnerabilityData populates the database with known vulnerabilities
func (v *VulnDatabase) initializeVulnerabilityData() {
	v.mu.Lock()
	defer v.mu.Unlock()
	
	// SSH Vulnerabilities
	v.serviceVulns["ssh"] = []Vulnerability{
		{
			ID:          "SSH-001",
			Name:        "OpenSSH Username Enumeration",
			Severity:    "Medium",
			Description: "OpenSSH versions before 7.7 allow username enumeration through timing attacks",
			CVE:         "CVE-2018-15473",
			CVSS:        5.3,
			Proof:       "Service version vulnerable to username enumeration",
		},
		{
			ID:          "SSH-002", 
			Name:        "OpenSSH SCP Escape Vulnerability",
			Severity:    "High",
			Description: "OpenSSH SCP allows command injection through crafted filenames",
			CVE:         "CVE-2020-15778",
			CVSS:        7.8,
			Proof:       "Service version vulnerable to SCP command injection",
		},
	}
	
	// HTTP/HTTPS Vulnerabilities
	v.serviceVulns["http"] = []Vulnerability{
		{
			ID:          "HTTP-001",
			Name:        "HTTP Server Information Disclosure",
			Severity:    "Low",
			Description: "HTTP server reveals version information in headers",
			CVE:         "",
			CVSS:        2.0,
			Proof:       "Server version disclosed in HTTP headers",
		},
	}
	
	v.serviceVulns["https"] = []Vulnerability{
		{
			ID:          "HTTPS-001",
			Name:        "SSL/TLS Weak Cipher Suites",
			Severity:    "Medium",
			Description: "HTTPS server supports weak cipher suites",
			CVE:         "",
			CVSS:        4.0,
			Proof:       "Weak SSL/TLS configuration detected",
		},
	}
	
	// FTP Vulnerabilities
	v.serviceVulns["ftp"] = []Vulnerability{
		{
			ID:          "FTP-001",
			Name:        "FTP Anonymous Login Enabled",
			Severity:    "Medium",
			Description: "FTP server allows anonymous authentication",
			CVE:         "",
			CVSS:        5.0,
			Proof:       "Anonymous FTP access allowed",
		},
	}
	
	// MySQL Vulnerabilities
	v.serviceVulns["mysql"] = []Vulnerability{
		{
			ID:          "MYSQL-001",
			Name:        "MySQL Weak Authentication",
			Severity:    "High",
			Description: "MySQL server uses weak authentication mechanism",
			CVE:         "",
			CVSS:        7.0,
			Proof:       "MySQL authentication weakness detected",
		},
	}
	
	// Banner patterns for vulnerability detection
	v.bannerPatterns = []BannerPattern{
		{
			Pattern:     regexp.MustCompile(`(?i)openssh[_\s]*([0-9]+\.[0-9]+)`),
			Service:     "ssh",
			VulnName:    "OpenSSH Version Detection",
			Description: "OpenSSH version detected, checking for known vulnerabilities",
			Severity:    "Info",
			CVE:         "",
			CVSS:        0.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)apache[_\s]*([0-9]+\.[0-9]+\.[0-9]+)`),
			Service:     "http",
			VulnName:    "Apache Version Detection",
			Description: "Apache HTTP server version detected",
			Severity:    "Info",
			CVE:         "",
			CVSS:        0.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)nginx[_\s]*([0-9]+\.[0-9]+\.[0-9]+)`),
			Service:     "http",
			VulnName:    "Nginx Version Detection", 
			Description: "Nginx web server version detected",
			Severity:    "Info",
			CVE:         "",
			CVSS:        0.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)vsftpd[_\s]*([0-9]+\.[0-9]+\.[0-9]+)`),
			Service:     "ftp",
			VulnName:    "vsftpd Version Detection",
			Description: "vsftpd FTP server detected",
			Severity:    "Info",
			CVE:         "",
			CVSS:        0.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)mysql[_\s]*([0-9]+\.[0-9]+)`),
			Service:     "mysql",
			VulnName:    "MySQL Version Detection",
			Description: "MySQL database server version detected",
			Severity:    "Info", 
			CVE:         "",
			CVSS:        0.0,
		},
	}
}

// generateVulnID creates a unique vulnerability ID
func generateVulnID(service, vulnName string) string {
	return strings.ToUpper(service) + "-" + strings.ReplaceAll(strings.ToLower(vulnName), " ", "_")
}

// AddVulnerability adds a new vulnerability to the database
func (v *VulnDatabase) AddVulnerability(service string, vuln Vulnerability) {
	v.mu.Lock()
	defer v.mu.Unlock()
	
	service = strings.ToLower(service)
	v.serviceVulns[service] = append(v.serviceVulns[service], vuln)
}

// AddBannerPattern adds a new banner pattern for vulnerability detection
func (v *VulnDatabase) AddBannerPattern(pattern BannerPattern) {
	v.mu.Lock()
	defer v.mu.Unlock()
	
	v.bannerPatterns = append(v.bannerPatterns, pattern)
}

// GetVulnerabilitiesBySeverity returns all vulnerabilities of a specific severity
func (v *VulnDatabase) GetVulnerabilitiesBySeverity(severity string) []Vulnerability {
	v.mu.RLock()
	defer v.mu.RUnlock()
	
	var vulns []Vulnerability
	severity = strings.ToLower(severity)
	
	for _, serviceVulns := range v.serviceVulns {
		for _, vuln := range serviceVulns {
			if strings.ToLower(vuln.Severity) == severity {
				vulns = append(vulns, vuln)
			}
		}
	}
	
	return vulns
}

// GetStatistics returns vulnerability statistics
func (v *VulnDatabase) GetStatistics() map[string]int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	
	stats := make(map[string]int)
	
	for _, serviceVulns := range v.serviceVulns {
		for _, vuln := range serviceVulns {
			stats[vuln.Severity]++
		}
	}
	
	return stats
}