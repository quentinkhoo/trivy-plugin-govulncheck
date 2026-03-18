package main

import (
	"fmt"
	"os"
	"context"

	"github.com/quentinkhoo/trivy-plugin-govulncheck/internal/image"
	"github.com/quentinkhoo/trivy-plugin-govulncheck/internal/trivy"
	"github.com/quentinkhoo/trivy-plugin-govulncheck/internal/govulncheck"
)

const usage = `Usage: trivy govulncheck image <ref>

Commands:
  image <ref>    Scan a container image for reachable Go vulnerabilities

Examples:
  trivy govulncheck image grafana/beyla:2.7.11
`

func main() {
	args := os.Args[1:]

	// To mimic the `trivy image` subcommand structure.
	if len(args) < 2 || args[0] != "image" {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	ref := args[1]
	fmt.Fprintf(os.Stderr, "scanning %s...\n", ref)

	report, err := trivy.RunTrivy(ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// We extract all "gobinary" results from the Trivy report
	var targets []string
	for _, result := range report.Results {
		if result.Type == "gobinary" {
			targets = append(targets, result.Target)
		}
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no Go binaries found in image")
		os.Exit(0)
	}

	// Extract the binaries from the image into a temp directory.
	binaries, err := image.ExtractBinaries(ref, targets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	for target, localPath := range binaries {
		fmt.Printf("extracted: %s -> %s\n", target, localPath)
	}

	// Run govulncheck on each extracted binary
	ctx := context.Background()
	reachableVulns := make(map[string]map[string]bool) // a map of binary -> CVE -> reachable
	for target, localPath := range binaries {
		vulns, err := govulncheck.RunGovulncheck(ctx, localPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			continue
		}
		reachableVulns[target] = vulns
	}

	// Print the results
	for target, vulns := range reachableVulns {
		fmt.Printf("%s: %v\n", target, vulns) 
	}

	// Finally lets cleanup the temp directory storing the extracted binaries.
	//image.CleanupTempDir()
}
