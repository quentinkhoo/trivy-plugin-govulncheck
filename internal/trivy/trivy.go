package trivy

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

type Report struct {
	SchemaVersion int             `json:"SchemaVersion"`                                                    
	Trivy         json.RawMessage `json:"Trivy,omitempty"`
	ReportID      string          `json:"ReportID,omitempty"`                                               
	CreatedAt     string          `json:"CreatedAt,omitempty"`
	ArtifactID    string          `json:"ArtifactID,omitempty"`                                             
	ArtifactName  string          `json:"ArtifactName"`                                                     
	ArtifactType  string          `json:"ArtifactType"`
	Metadata      json.RawMessage `json:"Metadata"`                                                         
	Results       []Result        `json:"Results"`                                                          
}

// Result represents one scanned target (e.g. a gobinary or OS package layer).                                      
type Result struct {
	Target          string            `json:"Target"`
	Class           string            `json:"Class"` 
	Type            string            `json:"Type"`                                                         
	Vulnerabilities []json.RawMessage `json:"Vulnerabilities,omitempty"`
} 

// Vulnerability is a single CVE finding within a Result.
type Vulnerability struct {
	VulnerabilityID  string              `json:"VulnerabilityID"`
	VendorIDs        []string            `json:"VendorIDs,omitempty"`
	PkgID            string              `json:"PkgID,omitempty"`
	PkgName          string              `json:"PkgName"`
	PkgIdentifier    json.RawMessage     `json:"PkgIdentifier,omitempty"`
	InstalledVersion string              `json:"InstalledVersion"`
	FixedVersion     string              `json:"FixedVersion,omitempty"`
	Status           string              `json:"Status,omitempty"`
	Layer            json.RawMessage     `json:"Layer,omitempty"`
	PrimaryURL       string              `json:"PrimaryURL,omitempty"`
	DataSource       json.RawMessage     `json:"DataSource,omitempty"`
	Fingerprint      string              `json:"Fingerprint,omitempty"`
	Title            string              `json:"Title,omitempty"`
	Description      string              `json:"Description,omitempty"`
	Severity         string              `json:"Severity"`
	VendorSeverity   json.RawMessage     `json:"VendorSeverity,omitempty"`
	CVSS             json.RawMessage     `json:"CVSS,omitempty"`
	References       []string            `json:"References,omitempty"`
	PublishedDate    string              `json:"PublishedDate,omitempty"`
	LastModifiedDate string              `json:"LastModifiedDate,omitempty"`
  }

// Run an internal Trivy command to scan the user-input imageRef and return the parsed report.
// Instead of calling the Trivy library directly, we shell out to the CLI to avoid any issues with vendoring or API stability. This also allows us to use the same Trivy binary that the user has installed, which may be more up-to-date than any vendored version.
// Also, easier to implement hehehe
func RunTrivy(ref string) (*Report, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", "--quiet", ref)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy exited with code %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("running trivy: %w", err)
	}

	var report Report
	if err = json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}
	return &report, nil
}
