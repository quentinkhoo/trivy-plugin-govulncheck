package trivy

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// We really only care about the "gobinary" results, but we define enough of the structure to parse the Trivy JSON output.
// https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types#Report
type Report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Metadata      Metadata `json:"Metadata"`
	Results       []Result `json:"Results"`
}

type Metadata struct {
	OS          *OS          `json:"OS,omitempty"`
	ImageConfig *ImageConfig `json:"ImageConfig,omitempty"`
}

type OS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type ImageConfig struct {
	Architecture string `json:"architecture,omitempty"`
	OS           string `json:"os,omitempty"`
}

// Result represents one scanned target (e.g. a gobinary or OS package layer).
type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
}

// Vulnerability is a single CVE finding within a Result.
type Vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion,omitempty"`
	Title            string   `json:"Title,omitempty"`
	Description      string   `json:"Description,omitempty"`
	Severity         string   `json:"Severity"`
	References       []string `json:"References,omitempty"`
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
