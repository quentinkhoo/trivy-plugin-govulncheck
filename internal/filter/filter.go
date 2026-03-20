package filter

import (
	"encoding/json"

	"trivy-plugin-govulncheck/internal/trivy"
)

// Given the original Trivy results and the map of reachableVulns, filter out the false positives
func FilterResults(results []trivy.Result, reachableVulns map[string]map[string]bool) []trivy.Result {

	var filteredResults []trivy.Result

	for _, result := range results {
		if result.Type != "gobinary" {
			filteredResults = append(filteredResults, result)
			continue
		}

		reachableVulnIDsForTarget := reachableVulns[result.Target]
		var actuallyReachableVulnsForTarget []json.RawMessage

		for _, rawVuln := range result.Vulnerabilities {
			var vuln struct {
				VulnerabilityID string `json:"VulnerabilityID"`
			}
			if err := json.Unmarshal(rawVuln, &vuln); err != nil {
				continue
			}
			if reachableVulnIDsForTarget[vuln.VulnerabilityID] {
				actuallyReachableVulnsForTarget = append(actuallyReachableVulnsForTarget, rawVuln)
			}
		}
		result.Vulnerabilities = actuallyReachableVulnsForTarget
		filteredResults = append(filteredResults, result)
	}
	return filteredResults
}
