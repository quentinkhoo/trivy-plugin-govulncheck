package main

import (
	"fmt"
	"os"
	"context"
	"encoding/json"

	"github.com/quentinkhoo/trivy-plugin-govulncheck/internal/filter"
	"github.com/quentinkhoo/trivy-plugin-govulncheck/internal/image"
	"github.com/quentinkhoo/trivy-plugin-govulncheck/internal/trivy"
	"github.com/quentinkhoo/trivy-plugin-govulncheck/internal/govulncheck"
)

const usage = `Usage: trivy govulncheck --image <ref> [-- <trivy flags>]
                                                                          
  Examples:                                                                                                     
    trivy govulncheck --image grafana/beyla:2.7.11                                                              
    trivy govulncheck --image grafana/beyla:2.7.11 -- --severity CRITICAL,HIGH --ignore-unfixed                 
  `

func main() {
	args := os.Args[1:]                                                                                           
                                                                                                                
  var ref string                                                                                                
  var extraArgs []string                                                                                        
                                                                                                                
  for i := 0; i < len(args); i++ {                                                                              
      if args[i] == "--image" && i+1 < len(args) {                                                              
          ref = args[i+1]                                                                                       
          i++                                                                                                   
      } else if args[i] == "--" {                                                                               
          extraArgs = args[i+1:]                                                                                
          break                                                                                                 
      }                                                 
  }    
   
  if ref == "" {                                                                                                
      fmt.Fprint(os.Stderr, usage)
      os.Exit(1)                                                                                                
  }

	report, err := trivy.RunTrivy(ref, extraArgs)
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
	report.Results = filter.FilterResults(report.Results, reachableVulns)
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))

	// Finally lets cleanup the temp directory storing the extracted binaries.
	image.CleanupTempDir()
}
