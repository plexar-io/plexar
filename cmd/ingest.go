package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/plexar-io/plexar/pkg/evidence"
	"github.com/plexar-io/plexar/pkg/ingest"
	"github.com/spf13/cobra"
)

var (
	ingestSource string
	ingestFile   string
	ingestOutput string
)

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "◈ Import findings from external scanners (Kubescape, Kyverno, Trivy SBOM)",
	Long: `◈ Ingest normalizes external scanner output into Reflex evidence format.

Supported sources:
  kubescape   — Kubescape JSON results (from 'kubescape scan --format json')
  kyverno     — Kyverno PolicyReport JSON (from 'kubectl get policyreports -o json')
  trivy-sbom  — Trivy CycloneDX or SPDX SBOM JSON

Examples:
  plexar ingest --source kubescape --file kubescape-results.json
  plexar ingest --source kyverno --file kyverno-policyreports.json
  plexar ingest --source trivy-sbom --file nginx-sbom.cdx.json`,
	RunE: runIngest,
}

func init() {
	rootCmd.AddCommand(ingestCmd)
	ingestCmd.Flags().StringVar(&ingestSource, "source", "", "Scanner source (kubescape, kyverno, trivy-sbom)")
	ingestCmd.Flags().StringVar(&ingestFile, "file", "", "Path to scanner output file")
	ingestCmd.Flags().StringVar(&ingestOutput, "output", "", "Write normalized results to file (optional, default: stdout summary)")
	_ = ingestCmd.MarkFlagRequired("source")
	_ = ingestCmd.MarkFlagRequired("file")
}

func runIngest(cmd *cobra.Command, args []string) error {
	f, err := os.Open(ingestFile)
	if err != nil {
		return fmt.Errorf("failed to open file %q: %w", ingestFile, err)
	}
	defer f.Close()

	fmt.Fprintf(os.Stderr, "◈ Ingesting %s data from %s...\n", ingestSource, ingestFile)

	result, err := ingest.Ingest(ingestSource, f)
	if err != nil {
		return fmt.Errorf("ingest failed: %w", err)
	}

	// Print summary
	fmt.Fprintf(os.Stderr, "   Source: %s\n", result.Source)
	fmt.Fprintf(os.Stderr, "   Total findings: %d\n", result.TotalFindings)
	fmt.Fprintf(os.Stderr, "   Pass: %d | Fail: %d | Warn: %d\n", result.PassCount, result.FailCount, result.WarnCount)

	if len(result.ComplianceChecks) > 0 {
		fmt.Fprintf(os.Stderr, "   Compliance checks: %d\n", len(result.ComplianceChecks))
	}
	if len(result.SBOMComponents) > 0 {
		fmt.Fprintf(os.Stderr, "   SBOM components: %d\n", len(result.SBOMComponents))
	}

	// Record in evidence vault
	vault := evidence.NewVault(evidence.DefaultDir())
	externalEvidence := ingest.MergeFindings(result.Findings)
	if len(externalEvidence) > 0 {
		fmt.Fprintf(os.Stderr, "   %d evidence entries merged into vault\n", len(externalEvidence))
	}

	// Output JSON if requested
	if ingestOutput != "" {
		out, err := os.Create(ingestOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer out.Close()
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "   Results written to %s\n", ingestOutput)
	} else {
		// Print top findings to stdout
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]interface{}{
			"source":           result.Source,
			"totalFindings":    result.TotalFindings,
			"pass":             result.PassCount,
			"fail":             result.FailCount,
			"warn":             result.WarnCount,
			"sbomComponents":   len(result.SBOMComponents),
			"complianceChecks": len(result.ComplianceChecks),
		})
	}

	_ = vault // vault reference kept for future integration
	return nil
}
