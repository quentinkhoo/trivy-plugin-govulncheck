// When we run a govulncheck -json command, it outputs a stream of JSON objects, like this:
// {"osv": {"id": "GO-2023-1234", "aliases":["CVE-2023-5678"]}}                                               
// {"osv": {"id": "GO-2024-9999", "aliases": ["CVE-2024-1111"]}}                                                 
// {"finding": {"osv": "GO-2023-1234", "trace": [...]}} 

// the findings are the results we care about, we just need to match the `osv` field
// in the findings to the `aliases` field in the osv entries to get the CVE IDs

package govulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"bytes"

	"golang.org/x/vuln/scan"
)

type Message struct {
     Finding *Finding    `json:"finding,omitempty"`
     OSV     *OSVEntry   `json:"osv,omitempty"`
 }

 // These are the "findings" (like no shit right?)
 type Finding struct {
     OSV string `json:"osv"`
 }

 // We need the OSVEntry alises to map back to CVE-styled IDs 
 type OSVEntry struct {
     ID      string   `json:"id"`
     Aliases []string `json:"aliases"`
 }

// Literally `govulncheck -mode=binary -json <binary>` but call the scan API instead
func RunGovulncheck(ctx context.Context, binaryPath string) (map[string]bool, error) {
	cmd := scan.Command(ctx, "-mode", "binary", "-json", binaryPath)
	
	// write the JSON output here instead of terminal
	var buf bytes.Buffer
	cmd.Stdout = &buf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting govulncheck: %w", err)
	}

	// by default when vulnerabilities are found, govulncheck would return an exit code of 3
	// we wanna skip these errors for now and move on with the code
	waitErr := cmd.Wait()

	osvAliasMapping := make(map[string][]string) //an OSV might have multiple CVEs
	reachableVulns := make(map[string]bool) // a map of CVEs on whether they're actually called in the binary

	// we need to use a json decoder here because govulncheck returns a JSON stream, not a single JSON object
	dec := json.NewDecoder(&buf)
	for dec.More() {
		var msg Message

		// now we try to decode each JSON object in the stream and handle the errors accordingly
		if err := dec.Decode(&msg); err != nil {
			if waitErr != nil {
				return nil, fmt.Errorf("running govulncheck: %w", waitErr)
			}
			return nil, fmt.Errorf("parsing govulncheck output: %w", err)
		}

		// we store the OSV ID mapping to the CVE/GHSA aliases in a map
		if msg.OSV != nil {
			for _, alias := range msg.OSV.Aliases {
				osvAliasMapping[msg.OSV.ID] = append(osvAliasMapping[msg.OSV.ID], alias)
			}
		}

		// for each finding
		if msg.Finding != nil {
			for _, cve := range osvAliasMapping[msg.Finding.OSV] {
				reachableVulns[cve] = true
			}
		}
	}

	return reachableVulns, nil
}
	