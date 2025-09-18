package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// ReportFormat represents the format of the report
type ReportFormat string

const (
	FormatJSON ReportFormat = "json"
	FormatCSV  ReportFormat = "csv"
	FormatPDF  ReportFormat = "pdf"
	FormatHTML ReportFormat = "html"
)

// ReportType represents the type of report
type ReportType string

const (
	TypeSummary   ReportType = "summary"
	TypeDetailed  ReportType = "detailed"
	TypeExecutive ReportType = "executive"
)

// Vulnerability represents a discovered vulnerability
type Vulnerability struct {
	ID              string    `json:"id"`
	Target          string    `json:"target"`
	Port            int       `json:"port"`
	Service         string    `json:"service"`
	Severity        string    `json:"severity"`
	CVE             string    `json:"cve,omitempty"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Recommendation  string    `json:"recommendation"`
	CVSSScore       float64   `json:"cvss_score"`
	RiskLevel       string    `json:"risk_level"`
	ExploitAvailable bool      `json:"exploit_available"`
	Timestamp       time.Time `json:"timestamp"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// ScanResult represents a complete scan result
type ScanResult struct {
	ScanID          string          `json:"scan_id"`
	ScanName        string          `json:"scan_name"`
	Targets         []string        `json:"targets"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	TotalHosts      int             `json:"total_hosts"`
	TotalPorts      int             `json:"total_ports"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         ScanSummary     `json:"summary"`
	Metadata        ReportMetadata  `json:"metadata"`
}

// ScanSummary provides statistical summary of the scan
type ScanSummary struct {
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	CriticalCount        int            `json:"critical_count"`
	HighCount            int            `json:"high_count"`
	MediumCount          int            `json:"medium_count"`
	LowCount             int            `json:"low_count"`
	InfoCount            int            `json:"info_count"`
	ByService            map[string]int `json:"by_service"`
	BySeverity           map[string]int `json:"by_severity"`
	ByPort               map[int]int    `json:"by_port"`
	ExploitableCount     int            `json:"exploitable_count"`
	AverageCVSS          float64        `json:"average_cvss"`
	RiskScore            float64        `json:"risk_score"`
}

// ReportMetadata contains metadata about the report
type ReportMetadata struct {
	GeneratedBy   string    `json:"generated_by"`
	GeneratedAt   time.Time `json:"generated_at"`
	ToolVersion   string    `json:"tool_version"`
	ReportFormat  string    `json:"report_format"`
	ReportType    string    `json:"report_type"`
	Organization  string    `json:"organization,omitempty"`
	ContactInfo   string    `json:"contact_info,omitempty"`
	Confidential  bool      `json:"confidential"`
}

// Reporter handles report generation
type Reporter struct {
	outputDir    string
	templatesDir string
	organization string
	contactInfo  string
}

// NewReporter creates a new reporter instance
func NewReporter(outputDir string) *Reporter {
	return &Reporter{
		outputDir:    outputDir,
		templatesDir: "templates/reports",
		organization: "VulnScanner Security Team",
		contactInfo:  "security@example.com",
	}
}

// SetOrganization sets the organization name for reports
func (r *Reporter) SetOrganization(org string) {
	r.organization = org
}

// SetContactInfo sets the contact information for reports
func (r *Reporter) SetContactInfo(info string) {
	r.contactInfo = info
}

// GenerateReport generates a report in the specified format
func (r *Reporter) GenerateReport(result ScanResult, format ReportFormat, reportType ReportType) (string, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(r.outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Set metadata
	result.Metadata = ReportMetadata{
		GeneratedBy:  "VulnScanner",
		GeneratedAt:  time.Now(),
		ToolVersion:  "1.0.0",
		ReportFormat: string(format),
		ReportType:   string(reportType),
		Organization: r.organization,
		ContactInfo:  r.contactInfo,
		Confidential: true,
	}

	// Generate report based on format
	switch format {
	case FormatJSON:
		return r.generateJSONReport(result, reportType)
	case FormatCSV:
		return r.generateCSVReport(result, reportType)
	case FormatPDF:
		return r.generatePDFReport(result, reportType)
	case FormatHTML:
		return r.generateHTMLReport(result, reportType)
	default:
		return "", fmt.Errorf("unsupported report format: %s", format)
	}
}

// generateJSONReport generates a JSON report
func (r *Reporter) generateJSONReport(result ScanResult, reportType ReportType) (string, error) {
	filename := fmt.Sprintf("vulnscan_report_%s_%s.json", result.ScanID, time.Now().Format("20060102_150405"))
	filepath := filepath.Join(r.outputDir, filename)

	// Filter data based on report type
	filteredResult := r.filterDataForReportType(result, reportType)

	data, err := json.MarshalIndent(filteredResult, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %v", err)
	}

	if err := ioutil.WriteFile(filepath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write JSON file: %v", err)
	}

	return filepath, nil
}

// generateCSVReport generates a CSV report
func (r *Reporter) generateCSVReport(result ScanResult, reportType ReportType) (string, error) {
	filename := fmt.Sprintf("vulnscan_report_%s_%s.csv", result.ScanID, time.Now().Format("20060102_150405"))
	filepath := filepath.Join(r.outputDir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"ID", "Target", "Port", "Service", "Severity", "CVE", "Title", "Description", "CVSS Score", "Risk Level", "Exploit Available", "Timestamp"}
	if err := writer.Write(header); err != nil {
		return "", fmt.Errorf("failed to write CSV header: %v", err)
	}

	// Filter vulnerabilities based on report type
	vulnerabilities := r.filterVulnerabilitiesForReportType(result.Vulnerabilities, reportType)

	// Write data rows
	for _, vuln := range vulnerabilities {
		row := []string{
			vuln.ID,
			vuln.Target,
			strconv.Itoa(vuln.Port),
			vuln.Service,
			vuln.Severity,
			vuln.CVE,
			vuln.Title,
			vuln.Description,
			fmt.Sprintf("%.1f", vuln.CVSSScore),
			vuln.RiskLevel,
			strconv.FormatBool(vuln.ExploitAvailable),
			vuln.Timestamp.Format("2006-01-02 15:04:05"),
		}
		if err := writer.Write(row); err != nil {
			return "", fmt.Errorf("failed to write CSV row: %v", err)
		}
	}

	return filepath, nil
}

// generatePDFReport generates a PDF report
func (r *Reporter) generatePDFReport(result ScanResult, reportType ReportType) (string, error) {
	filename := fmt.Sprintf("vulnscan_report_%s_%s.pdf", result.ScanID, time.Now().Format("20060102_150405"))
	filepath := filepath.Join(r.outputDir, filename)

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Set font
	pdf.SetFont("Arial", "B", 16)

	// Title page
	r.generatePDFTitlePage(pdf, result, reportType)

	// Executive summary
	if reportType == TypeExecutive || reportType == TypeDetailed {
		r.generatePDFExecutiveSummary(pdf, result)
	}

	// Detailed findings
	if reportType == TypeDetailed {
		r.generatePDFDetailedFindings(pdf, result)
	}

	// Statistics
	r.generatePDFStatistics(pdf, result)

	// Recommendations
	r.generatePDFRecommendations(pdf, result)

	// Save PDF
	if err := pdf.Error(); err != nil {
		return "", fmt.Errorf("PDF generation error: %v", err)
	}

	if err := pdf.OutputFileAndClose(filepath); err != nil {
		return "", fmt.Errorf("failed to save PDF: %v", err)
	}

	return filepath, nil
}

// generatePDFTitlePage creates the title page
func (r *Reporter) generatePDFTitlePage(pdf *gofpdf.Fpdf, result ScanResult, reportType ReportType) {
	pdf.SetFont("Arial", "B", 24)
	pdf.Cell(0, 20, "Vulnerability Assessment Report")
	pdf.Ln(15)

	pdf.SetFont("Arial", "B", 18)
	pdf.Cell(0, 15, fmt.Sprintf("Scan ID: %s", result.ScanID))
	pdf.Ln(12)

	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, fmt.Sprintf("Scan Name: %s", result.ScanName))
	pdf.Ln(8)
	pdf.Cell(0, 10, fmt.Sprintf("Report Type: %s", reportType))
	pdf.Ln(8)
	pdf.Cell(0, 10, fmt.Sprintf("Generated: %s", result.Metadata.GeneratedAt.Format("2006-01-02 15:04:05")))
	pdf.Ln(8)
	pdf.Cell(0, 10, fmt.Sprintf("Duration: %s", result.Duration))
	pdf.Ln(8)
	pdf.Cell(0, 10, fmt.Sprintf("Total Vulnerabilities: %d", result.Summary.TotalVulnerabilities))
	pdf.Ln(20)

	// Confidentiality notice
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 10, "CONFIDENTIAL - FOR AUTHORIZED USE ONLY")
	pdf.Ln(15)
}

// generatePDFExecutiveSummary creates executive summary
func (r *Reporter) generatePDFExecutiveSummary(pdf *gofpdf.Fpdf, result ScanResult) {
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.Cell(0, 15, "Executive Summary")
	pdf.Ln(12)

	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 8, fmt.Sprintf("This vulnerability assessment identified %d security vulnerabilities across %d hosts and %d ports. The scan was conducted from %s to %s, covering targets including %s.",
		result.Summary.TotalVulnerabilities, result.Summary.TotalVulnerabilities, result.TotalPorts,
		result.StartTime.Format("2006-01-02 15:04"), result.EndTime.Format("2006-01-02 15:04"),
		strings.Join(result.Targets, ", ")), "", "", false)
	pdf.Ln(10)

	// Risk summary
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 12, "Risk Summary")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 8, fmt.Sprintf("Critical: %d", result.Summary.CriticalCount))
	pdf.Ln(6)
	pdf.Cell(0, 8, fmt.Sprintf("High: %d", result.Summary.HighCount))
	pdf.Ln(6)
	pdf.Cell(0, 8, fmt.Sprintf("Medium: %d", result.Summary.MediumCount))
	pdf.Ln(6)
	pdf.Cell(0, 8, fmt.Sprintf("Low: %d", result.Summary.LowCount))
	pdf.Ln(10)
}

// generatePDFDetailedFindings creates detailed findings section
func (r *Reporter) generatePDFDetailedFindings(pdf *gofpdf.Fpdf, result ScanResult) {
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.Cell(0, 15, "Detailed Findings")
	pdf.Ln(12)

	for i, vuln := range result.Vulnerabilities {
		if i > 0 && i%3 == 0 { // New page every 3 vulnerabilities
			pdf.AddPage()
		}

		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 10, fmt.Sprintf("%d. %s", i+1, vuln.Title))
		pdf.Ln(8)

		pdf.SetFont("Arial", "", 12)
		pdf.Cell(0, 8, fmt.Sprintf("Target: %s:%d", vuln.Target, vuln.Port))
		pdf.Ln(6)
		pdf.Cell(0, 8, fmt.Sprintf("Service: %s", vuln.Service))
		pdf.Ln(6)
		pdf.Cell(0, 8, fmt.Sprintf("Severity: %s (CVSS: %.1f)", vuln.Severity, vuln.CVSSScore))
		pdf.Ln(6)
		if vuln.CVE != "" {
			pdf.Cell(0, 8, fmt.Sprintf("CVE: %s", vuln.CVE))
			pdf.Ln(6)
		}

		pdf.SetFont("Arial", "B", 12)
		pdf.Cell(0, 8, "Description:")
		pdf.Ln(6)
		pdf.SetFont("Arial", "", 12)
		pdf.MultiCell(0, 6, vuln.Description, "", "", false)
		pdf.Ln(6)

		if vuln.Recommendation != "" {
			pdf.SetFont("Arial", "B", 12)
			pdf.Cell(0, 8, "Recommendation:")
			pdf.Ln(6)
			pdf.SetFont("Arial", "", 12)
			pdf.MultiCell(0, 6, vuln.Recommendation, "", "", false)
			pdf.Ln(8)
		}
	}
}

// generatePDFStatistics creates statistics section
func (r *Reporter) generatePDFStatistics(pdf *gofpdf.Fpdf, result ScanResult) {
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.Cell(0, 15, "Statistics")
	pdf.Ln(12)

	// Vulnerability by service
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 12, "Vulnerabilities by Service")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 12)
	for service, count := range result.Summary.ByService {
		pdf.Cell(0, 8, fmt.Sprintf("%s: %d", service, count))
		pdf.Ln(6)
	}
	pdf.Ln(8)

	// Vulnerability by severity
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 12, "Vulnerabilities by Severity")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 12)
	for severity, count := range result.Summary.BySeverity {
		pdf.Cell(0, 8, fmt.Sprintf("%s: %d", severity, count))
		pdf.Ln(6)
	}
}

// generatePDFRecommendations creates recommendations section
func (r *Reporter) generatePDFRecommendations(pdf *gofpdf.Fpdf, result ScanResult) {
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.Cell(0, 15, "Recommendations")
	pdf.Ln(12)

	pdf.SetFont("Arial", "", 12)
	recommendations := r.generateRecommendations(result)
	
	for i, rec := range recommendations {
		pdf.SetFont("Arial", "B", 12)
		pdf.Cell(0, 10, fmt.Sprintf("%d. %s", i+1, rec.Title))
		pdf.Ln(8)
		
		pdf.SetFont("Arial", "", 12)
		pdf.MultiCell(0, 6, rec.Description, "", "", false)
		pdf.Ln(8)
	}
}

// generateHTMLReport generates an HTML report
func (r *Reporter) generateHTMLReport(result ScanResult, reportType ReportType) (string, error) {
	filename := fmt.Sprintf("vulnscan_report_%s_%s.html", result.ScanID, time.Now().Format("20060102_150405"))
	filepath := filepath.Join(r.outputDir, filename)

	// Filter data based on report type
	filteredResult := r.filterDataForReportType(result, reportType)

	htmlTemplate := r.getHTMLTemplate(reportType)
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"formatDate": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"formatDuration": func(d time.Duration) string { return d.String() },
		"lower": strings.ToLower,
	}).Parse(htmlTemplate)
	
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML template: %v", err)
	}

	file, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create HTML file: %v", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, filteredResult); err != nil {
		return "", fmt.Errorf("failed to execute HTML template: %v", err)
	}

	return filepath, nil
}

// Helper functions

func (r *Reporter) filterDataForReportType(result ScanResult, reportType ReportType) ScanResult {
	switch reportType {
	case TypeSummary:
		// Only include high-level summary
		result.Vulnerabilities = []Vulnerability{}
		return result
	case TypeExecutive:
		// Include only high and critical severity
		var filteredVulns []Vulnerability
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity == "Critical" || vuln.Severity == "High" {
				filteredVulns = append(filteredVulns, vuln)
			}
		}
		result.Vulnerabilities = filteredVulns
		return result
	case TypeDetailed:
		// Include all vulnerabilities
		return result
	default:
		return result
	}
}

func (r *Reporter) filterVulnerabilitiesForReportType(vulnerabilities []Vulnerability, reportType ReportType) []Vulnerability {
	switch reportType {
	case TypeExecutive:
		var filtered []Vulnerability
		for _, vuln := range vulnerabilities {
			if vuln.Severity == "Critical" || vuln.Severity == "High" {
				filtered = append(filtered, vuln)
			}
		}
		return filtered
	default:
		return vulnerabilities
	}
}

type Recommendation struct {
	Title       string
	Description string
	Priority    string
}

func (r *Reporter) generateRecommendations(result ScanResult) []Recommendation {
	var recommendations []Recommendation
	
	if result.Summary.CriticalCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Title:       "Address Critical Vulnerabilities Immediately",
			Description: fmt.Sprintf("There are %d critical vulnerabilities that require immediate attention. These pose the highest risk to your infrastructure and should be patched or mitigated within 24-48 hours.", result.Summary.CriticalCount),
			Priority:    "Critical",
		})
	}
	
	if result.Summary.HighCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Title:       "Prioritize High-Risk Vulnerabilities",
			Description: fmt.Sprintf("Address the %d high-severity vulnerabilities within the next 7 days. These could be exploited to gain unauthorized access or disrupt services.", result.Summary.HighCount),
			Priority:    "High",
		})
	}
	
	if result.Summary.ExploitableCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Title:       "Focus on Exploitable Vulnerabilities",
			Description: fmt.Sprintf("%d vulnerabilities have publicly available exploits. These should be prioritized for patching as attackers can easily leverage them.", result.Summary.ExploitableCount),
			Priority:    "High",
		})
	}
	
	// Add service-specific recommendations
	for service, count := range result.Summary.ByService {
		if count > 5 {
			recommendations = append(recommendations, Recommendation{
				Title:       fmt.Sprintf("Review %s Service Configuration", strings.ToUpper(service)),
				Description: fmt.Sprintf("The %s service has %d identified vulnerabilities. Consider implementing additional security hardening measures and keeping the service updated.", service, count),
				Priority:    "Medium",
			})
		}
	}
	
	return recommendations
}

func (r *Reporter) getHTMLTemplate(reportType ReportType) string {
	switch reportType {
	case TypeSummary:
		return r.getSummaryHTMLTemplate()
	case TypeExecutive:
		return r.getExecutiveHTMLTemplate()
	case TypeDetailed:
		return r.getDetailedHTMLTemplate()
	default:
		return r.getDetailedHTMLTemplate()
	}
}

func (r *Reporter) getSummaryHTMLTemplate() string {
	return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Summary Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; font-family: Arial, sans-serif; }
        .report-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 15px; }
        .metric-card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .confidential { background: #dc3545; color: white; padding: 10px; border-radius: 5px; text-align: center; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="report-header text-center mb-4">
            <h1>Vulnerability Assessment Summary</h1>
            <p class="mb-0">Scan ID: {{.ScanID}} | Generated: {{formatDate .Metadata.GeneratedAt}}</p>
        </div>
        
        <div class="confidential mb-4">
            <strong>CONFIDENTIAL - FOR AUTHORIZED USE ONLY</strong>
        </div>
        
        <div class="row">
            <div class="col-md-3">
                <div class="metric-card text-center">
                    <h3>{{.Summary.TotalVulnerabilities}}</h3>
                    <p class="mb-0">Total Vulnerabilities</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card text-center">
                    <h3>{{.Summary.CriticalCount}}</h3>
                    <p class="mb-0">Critical</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card text-center">
                    <h3>{{.Summary.HighCount}}</h3>
                    <p class="mb-0">High</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card text-center">
                    <h3>{{.Summary.ExploitableCount}}</h3>
                    <p class="mb-0">Exploitable</p>
                </div>
            </div>
        </div>
        
        <div class="mt-4">
            <h4>Scan Information</h4>
            <table class="table table-bordered">
                <tr><td><strong>Scan Duration:</strong></td><td>{{formatDuration .Duration}}</td></tr>
                <tr><td><strong>Total Hosts:</strong></td><td>{{.TotalHosts}}</td></tr>
                <tr><td><strong>Total Ports:</strong></td><td>{{.TotalPorts}}</td></tr>
                <tr><td><strong>Average CVSS Score:</strong></td><td>{{printf "%.1f" .Summary.AverageCVSS}}</td></tr>
            </table>
        </div>
    </div>
</body>
</html>`
}

func (r *Reporter) getExecutiveHTMLTemplate() string {
	return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Vulnerability Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #f8f9fa; font-family: Arial, sans-serif; }
        .report-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 15px; }
        .metric-card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .confidential { background: #dc3545; color: white; padding: 10px; border-radius: 5px; text-align: center; }
        .vulnerability-item { background: white; border-radius: 8px; padding: 15px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .severity-critical { border-left: 5px solid #dc3545; }
        .severity-high { border-left: 5px solid #fd7e14; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="report-header text-center mb-4">
            <h1>Executive Vulnerability Assessment Report</h1>
            <p class="mb-0">Scan ID: {{.ScanID}} | Generated: {{formatDate .Metadata.GeneratedAt}}</p>
        </div>
        
        <div class="confidential mb-4">
            <strong>CONFIDENTIAL - FOR AUTHORIZED USE ONLY</strong>
        </div>
        
        <!-- Executive Summary -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="metric-card">
                    <h3>Executive Summary</h3>
                    <p>This vulnerability assessment identified <strong>{{.Summary.TotalVulnerabilities}}</strong> security vulnerabilities across {{.TotalHosts}} hosts and {{.TotalPorts}} ports. The scan was conducted from {{formatDate .StartTime}} to {{formatDate .EndTime}}, covering targets including {{range $i, $target := .Targets}}{{if $i}}, {{end}}{{$target}}{{end}}.</p>
                    
                    <div class="row mt-3">
                        <div class="col-md-6">
                            <canvas id="severityChart" width="400" height="200"></canvas>
                        </div>
                        <div class="col-md-6">
                            <h5>Risk Summary</h5>
                            <ul class="list-unstyled">
                                <li><span class="badge bg-danger">Critical:</span> {{.Summary.CriticalCount}} vulnerabilities</li>
                                <li><span class="badge bg-warning">High:</span> {{.Summary.HighCount}} vulnerabilities</li>
                                <li><span class="badge bg-info">Medium:</span> {{.Summary.MediumCount}} vulnerabilities</li>
                                <li><span class="badge bg-secondary">Low:</span> {{.Summary.LowCount}} vulnerabilities</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Critical and High Vulnerabilities -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="metric-card">
                    <h3>Critical and High Priority Vulnerabilities</h3>
                    {{range .Vulnerabilities}}
                    <div class="vulnerability-item {{if eq .Severity "Critical"}}severity-critical{{else}}severity-high{{end}}">
                        <h5>{{.Title}}</h5>
                        <p><strong>Target:</strong> {{.Target}}:{{.Port}} | <strong>Service:</strong> {{.Service}} | <strong>CVSS:</strong> {{.CVSSScore}}</p>
                        <p>{{.Description}}</p>
                        {{if .Recommendation}}
                        <p><strong>Recommendation:</strong> {{.Recommendation}}</p>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
        </div>
        
        <!-- Recommendations -->
        <div class="row">
            <div class="col-12">
                <div class="metric-card">
                    <h3>Key Recommendations</h3>
                    <ol>
                        <li><strong>Address Critical Vulnerabilities Immediately:</strong> Focus on the {{.Summary.CriticalCount}} critical vulnerabilities that pose the highest risk.</li>
                        <li><strong>Prioritize High-Risk Issues:</strong> Address {{.Summary.HighCount}} high-severity vulnerabilities within the next 7 days.</li>
                        <li><strong>Implement Security Patches:</strong> Establish a regular patch management process to prevent future vulnerabilities.</li>
                        <li><strong>Review Service Configurations:</strong> Harden services with multiple identified vulnerabilities.</li>
                    </ol>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Severity distribution chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [{{.Summary.CriticalCount}}, {{.Summary.HighCount}}, {{.Summary.MediumCount}}, {{.Summary.LowCount}}, {{.Summary.InfoCount}}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#6c757d']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Vulnerability Distribution'
                    }
                }
            }
        });
    </script>
</body>
</html>`
}

func (r *Reporter) getDetailedHTMLTemplate() string {
	return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Detailed Vulnerability Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #f8f9fa; font-family: Arial, sans-serif; }
        .report-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 15px; }
        .metric-card { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .confidential { background: #dc3545; color: white; padding: 10px; border-radius: 5px; text-align: center; }
        .vulnerability-item { background: white; border-radius: 8px; padding: 15px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .severity-critical { border-left: 5px solid #dc3545; }
        .severity-high { border-left: 5px solid #fd7e14; }
        .severity-medium { border-left: 5px solid #ffc107; }
        .severity-low { border-left: 5px solid #28a745; }
        .severity-info { border-left: 5px solid #6c757d; }
        .filter-controls { margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="report-header text-center mb-4">
            <h1>Detailed Vulnerability Assessment Report</h1>
            <p class="mb-0">Scan ID: {{.ScanID}} | Generated: {{formatDate .Metadata.GeneratedAt}}</p>
        </div>
        
        <div class="confidential mb-4">
            <strong>CONFIDENTIAL - FOR AUTHORIZED USE ONLY</strong>
        </div>
        
        <!-- Executive Summary -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="metric-card">
                    <h3>Executive Summary</h3>
                    <div class="row">
                        <div class="col-md-8">
                            <p>This comprehensive vulnerability assessment identified <strong>{{.Summary.TotalVulnerabilities}}</strong> security vulnerabilities across {{.TotalHosts}} hosts and {{.TotalPorts}} ports. The scan was conducted from {{formatDate .StartTime}} to {{formatDate .EndTime}}, covering targets including {{range $i, $target := .Targets}}{{if $i}}, {{end}}{{$target}}{{end}}.</p>
                            <p><strong>Average CVSS Score:</strong> {{printf "%.1f" .Summary.AverageCVSS}} | <strong>Risk Score:</strong> {{printf "%.1f" .Summary.RiskScore}}</p>
                        </div>
                        <div class="col-md-4">
                            <canvas id="severityChart" width="300" height="150"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Statistics Overview -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="metric-card">
                    <h4>Vulnerabilities by Service</h4>
                    <canvas id="serviceChart" width="400" height="200"></canvas>
                </div>
            </div>
            <div class="col-md-6">
                <div class="metric-card">
                    <h4>Vulnerabilities by Port</h4>
                    <canvas id="portChart" width="400" height="200"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Filter Controls -->
        <div class="filter-controls">
            <div class="metric-card">
                <h4>Filter Vulnerabilities</h4>
                <div class="row">
                    <div class="col-md-3">
                        <label for="severityFilter">Severity:</label>
                        <select id="severityFilter" class="form-select">
                            <option value="">All</option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                            <option value="Info">Info</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label for="serviceFilter">Service:</label>
                        <select id="serviceFilter" class="form-select">
                            <option value="">All</option>
                            {{range $service, $count := .Summary.ByService}}
                            <option value="{{$service}}">{{$service}} ({{$count}})</option>
                            {{end}}
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label for="exploitFilter">Exploit Available:</label>
                        <select id="exploitFilter" class="form-select">
                            <option value="">All</option>
                            <option value="true">Yes</option>
                            <option value="false">No</option>
                        </select>
                    </div>
                    <div class="col-md-3 d-flex align-items-end">
                        <button onclick="filterVulnerabilities()" class="btn btn-primary">Apply Filter</button>
                        <button onclick="clearFilters()" class="btn btn-secondary ms-2">Clear</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- All Vulnerabilities -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="metric-card">
                    <h3>All Vulnerabilities ({{len .Vulnerabilities}})</h3>
                    <div id="vulnerabilityList">
                        {{range .Vulnerabilities}}
                        <div class="vulnerability-item severity-{{lower .Severity}}" data-severity="{{.Severity}}" data-service="{{.Service}}" data-exploit="{{.ExploitAvailable}}">
                            <div class="row">
                                <div class="col-md-8">
                                    <h5>{{.Title}}</h5>
                                    <p><strong>Target:</strong> {{.Target}}:{{.Port}} | <strong>Service:</strong> {{.Service}} | <strong>CVSS:</strong> {{.CVSSScore}}</p>
                                    <p>{{.Description}}</p>
                                    {{if .CVE}}
                                    <p><strong>CVE:</strong> <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={{.CVE}}" target="_blank">{{.CVE}}</a></p>
                                    {{end}}
                                    {{if .Recommendation}}
                                    <p><strong>Recommendation:</strong> {{.Recommendation}}</p>
                                    {{end}}
                                </div>
                                <div class="col-md-4">
                                    <div class="text-end">
                                        <span class="badge bg-{{if eq .Severity "Critical"}}danger{{else if eq .Severity "High"}}warning{{else if eq .Severity "Medium"}}info{{else if eq .Severity "Low"}}success{{else}}secondary{{end}}">{{.Severity}}</span>
                                        {{if .ExploitAvailable}}
                                        <span class="badge bg-dark">Exploit Available</span>
                                        {{end}}
                                        <br><small class="text-muted">{{formatDate .Timestamp}}</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                        {{end}}
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Recommendations -->
        <div class="row">
            <div class="col-12">
                <div class="metric-card">
                    <h3>Recommendations</h3>
                    <ol>
                        <li><strong>Address Critical Vulnerabilities Immediately:</strong> Focus on the {{.Summary.CriticalCount}} critical vulnerabilities that pose the highest risk.</li>
                        <li><strong>Prioritize High-Risk Issues:</strong> Address {{.Summary.HighCount}} high-severity vulnerabilities within the next 7 days.</li>
                        <li><strong>Focus on Exploitable Vulnerabilities:</strong> {{.Summary.ExploitableCount}} vulnerabilities have publicly available exploits and should be prioritized.</li>
                        <li><strong>Implement Security Patches:</strong> Establish a regular patch management process to prevent future vulnerabilities.</li>
                        <li><strong>Review Service Configurations:</strong> Harden services with multiple identified vulnerabilities.</li>
                    </ol>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Severity distribution chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [{{.Summary.CriticalCount}}, {{.Summary.HighCount}}, {{.Summary.MediumCount}}, {{.Summary.LowCount}}, {{.Summary.InfoCount}}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#6c757d']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Severity Distribution'
                    }
                }
            }
        });
        
        // Service chart
        const serviceCtx = document.getElementById('serviceChart').getContext('2d');
        new Chart(serviceCtx, {
            type: 'bar',
            data: {
                labels: [{{range $service, $count := .Summary.ByService}}'{{$service}}',{{end}}],
                datasets: [{
                    label: 'Vulnerabilities by Service',
                    data: [{{range $service, $count := .Summary.ByService}}{{$count}},{{end}}],
                    backgroundColor: '#667eea'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Port chart
        const portCtx = document.getElementById('portChart').getContext('2d');
        new Chart(portCtx, {
            type: 'line',
            data: {
                labels: [{{range $port, $count := .Summary.ByPort}}{{$port}},{{end}}],
                datasets: [{
                    label: 'Vulnerabilities by Port',
                    data: [{{range $port, $count := .Summary.ByPort}}{{$count}},{{end}}],
                    borderColor: '#764ba2',
                    fill: false
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Filter functionality
        function filterVulnerabilities() {
            const severity = document.getElementById('severityFilter').value;
            const service = document.getElementById('serviceFilter').value;
            const exploit = document.getElementById('exploitFilter').value;
            
            const items = document.querySelectorAll('.vulnerability-item');
            items.forEach(item => {
                let show = true;
                
                if (severity && !item.classList.contains('severity-' + severity.toLowerCase())) {
                    show = false;
                }
                
                if (service && item.dataset.service !== service) {
                    show = false;
                }
                
                if (exploit && item.dataset.exploit !== exploit) {
                    show = false;
                }
                
                item.style.display = show ? 'block' : 'none';
            });
        }
        
        function clearFilters() {
            document.getElementById('severityFilter').value = '';
            document.getElementById('serviceFilter').value = '';
            document.getElementById('exploitFilter').value = '';
            filterVulnerabilities();
        }
    </script>
</body>
</html>`
}

// Helper function to convert string to lowercase for template
func lower(s string) string {
	return strings.ToLower(s)
}