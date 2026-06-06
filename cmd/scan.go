package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/plexar-io/plexar/pkg/api"
	"github.com/plexar-io/plexar/pkg/evidence"
	"github.com/plexar-io/plexar/pkg/integrations"
	"github.com/plexar-io/plexar/pkg/preflight"
	"github.com/plexar-io/plexar/pkg/report"
	"github.com/plexar-io/plexar/pkg/reporter"
	"github.com/plexar-io/plexar/pkg/scanner"
	"github.com/spf13/cobra"
)

// resolveNamespaces turns the --namespace / --all-namespaces flags into a concrete list.
func resolveNamespaces() ([]string, error) {
	if allNamespaces {
		ns, err := api.ListNamespaces(kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to list namespaces: %w", err)
		}
		if len(ns) == 0 {
			return nil, fmt.Errorf("no non-system namespaces found")
		}
		return ns, nil
	}

	// Support comma-separated: -n production,staging,monitoring
	parts := strings.Split(namespace, ",")
	var namespaces []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			namespaces = append(namespaces, p)
		}
	}
	if len(namespaces) == 0 {
		return []string{"default"}, nil
	}
	return namespaces, nil
}

var (
	outputFormat   string
	vulnSource     string
	freshScan      bool
	scanVantaToken string
	scanDrataKey   string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "◈ Run a one-time blast radius scan",
	Long: `◈ Scans the target namespace for pods, discovers vulnerabilities, maps network
reachability, and computes blast radius scores for every pod.

Vulnerability sources:
  trivy (default)    — runs trivy binary to scan container images
  trivy-operator     — reads existing Trivy Operator VulnerabilityReport CRDs
  none               — skip CVE scanning, score on blast radius + permissions only

Output formats:
  table (default) — colorized CLI table
  json            — full scan result as JSON
  csv             — flat per-pod CSV
  sarif           — SARIF format for GitHub Security tab
  *.pdf           — SOC 2 or EU AI Act compliance report`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, csv, sarif")
	scanCmd.Flags().StringVar(&vulnSource, "vuln-source", "trivy", "Vulnerability source: trivy, trivy-operator, none")
	scanCmd.Flags().BoolVar(&freshScan, "fresh", false, "Force re-scan images (ignore cache)")
	scanCmd.Flags().StringVar(&scanVantaToken, "vanta-token", "", "Vanta API token — push evidence after scan")
	scanCmd.Flags().StringVar(&scanDrataKey, "drata-key", "", "Drata API key — push evidence after scan")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Determine progress output
	var progress *os.File
	if outputFormat == "table" {
		progress = os.Stderr
	}

	// Configure vulnerability source with progress and cache options
	opts := scanner.SourceOptions{Fresh: freshScan}
	if progress != nil {
		opts.Progress = progress
	}
	source, err := scanner.NewSource(vulnSource, opts)
	if err != nil {
		return err
	}
	api.ActiveVulnSource = source

	// Resolve target namespaces
	namespaces, err := resolveNamespaces()
	if err != nil {
		return err
	}

	// Preflight checks (skip Trivy checks when vuln-source=none)
	if vulnSource != "none" {
		for _, ns := range namespaces {
			if err := preflight.Run(kubeconfig, ns); err != nil {
				return err
			}
		}
	}

	result, err := api.RunMultiNamespaceScan(kubeconfig, namespaces, progress)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// PDF output: detect .pdf extension
	if strings.HasSuffix(strings.ToLower(outputFormat), ".pdf") {
		pdfPath := outputFormat
		baseName := strings.ToLower(pdfPath)

		// EU AI Act Annex IV report if filename contains "euai" or "annex"
		if strings.Contains(baseName, "euai") || strings.Contains(baseName, "annex") || strings.Contains(baseName, "ai-act") {
			annexReport := report.GenerateAnnexIVReport(result)
			if err := report.GenerateAnnexIVPDF(result, pdfPath); err != nil {
				return fmt.Errorf("EU AI Act PDF generation failed: %w", err)
			}
			fmt.Fprintf(os.Stderr, "\n\U0001f1ea\U0001f1fa EU AI Act Annex IV Report → %s\n\n", pdfPath)
			for _, s := range annexReport.Sections {
				icon := "✅"
				if s.Status == "gap" {
					icon = "❌"
				} else if s.Status == "partial" {
					icon = "⚠️"
				}
				fmt.Fprintf(os.Stderr, "  %s %s %3d/100 %s\n", icon, s.ID, s.Score, s.Title)
			}
			fmt.Fprintf(os.Stderr, "\n  Overall: %d/100 — %s | %d sections | %d AI workloads\n",
				annexReport.OverallScore, annexReport.RiskLevel, len(annexReport.Sections), annexReport.AIWorkloads)
			return nil
		}

		// Default: SOC 2 report
		if err := report.GenerateSOC2PDF(result, pdfPath); err != nil {
			return fmt.Errorf("PDF generation failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "\n\U0001f4cb SOC 2 Compliance Report → %s\n\n", pdfPath)
		for _, comp := range result.Compliance {
			if comp.Framework == "SOC 2" {
				for _, c := range comp.Controls {
					icon := "✅"
					if c.Status == "fail" {
						icon = "❌"
					} else if c.Status == "partial" {
						icon = "⚠️"
					}
					fmt.Fprintf(os.Stderr, "  %s %s %3d/100 %s\n", icon, c.ID, c.Score, c.Name)
				}
				fmt.Fprintf(os.Stderr, "\n  Overall: %d/100 | %d/%d controls passing\n", comp.Score, comp.Passing, comp.TotalChecks)
			}
		}
		return nil
	}

	// Push evidence to compliance platforms if configured
	if scanVantaToken != "" || scanDrataKey != "" {
		vault := evidence.NewVault(evidence.DefaultDir())
		vault.Record(result)
		intMgr := integrations.NewManager()
		if scanVantaToken != "" {
			intMgr.AddVanta(scanVantaToken)
		}
		if scanDrataKey != "" {
			intMgr.AddDrata(scanDrataKey)
		}
		records := vault.List(result.ScanTime.Add(-1*time.Minute), time.Time{})
		if len(records) > 0 {
			latest := records[len(records)-1]
			if errs := intMgr.PushEvidence(&latest); len(errs) > 0 {
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "\u26a0  Evidence push failed: %v\n", e)
				}
			} else {
				fmt.Fprintf(os.Stderr, "\U0001f4e4 Evidence pushed to compliance platforms\n")
			}
			if errs := intMgr.PushControls(latest.Controls, result.ClusterName); len(errs) > 0 {
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "\u26a0  Controls push failed: %v\n", e)
				}
			} else {
				fmt.Fprintf(os.Stderr, "\U0001f4e4 Controls pushed (%d controls)\n", len(latest.Controls))
			}
		}
	}

	switch outputFormat {
	case "json":
		return reporter.ExportJSON(os.Stdout, result)
	case "csv":
		return reporter.ExportCSV(os.Stdout, result)
	case "sarif":
		return reporter.ExportSARIF(os.Stdout, result)
	default:
		reporter.PrintReport(os.Stdout, result)
		return nil
	}
}
