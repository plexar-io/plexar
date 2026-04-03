package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/plexar-security/plexar/pkg/api"
	"github.com/plexar-security/plexar/pkg/netpol"
	"github.com/spf13/cobra"
)

var (
	genOutputFormat string
	genApply        bool
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "◈ Generate Kubernetes resources based on scan results",
}

var generateNetpolCmd = &cobra.Command{
	Use:   "netpol",
	Short: "◈ Generate NetworkPolicies for unprotected pods, prioritized by blast radius",
	Long: `Scans the namespace, identifies pods without NetworkPolicies, and generates
risk-prioritized NetworkPolicy YAML. Pods with the highest blast radius score
get policies first.

Output is valid Kubernetes YAML that can be piped directly to kubectl apply.`,
	Example: `  # Preview generated policies
  plexar generate netpol --namespace production

  # Output as JSON
  plexar generate netpol --namespace production -o json

  # Apply directly
  plexar generate netpol --namespace production | kubectl apply -f -`,
	RunE: runGenerateNetpol,
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(generateNetpolCmd)
	generateNetpolCmd.Flags().StringVarP(&genOutputFormat, "output", "o", "yaml", "Output format: yaml, json")
}

func runGenerateNetpol(cmd *cobra.Command, args []string) error {
	result, err := api.RunScan(kubeconfig, namespace, os.Stderr)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	policies := netpol.Generate(result.Scores, namespace)

	if len(policies) == 0 {
		fmt.Fprintf(os.Stderr, "✅ All pods in namespace '%s' already have NetworkPolicies. Nothing to generate.\n", namespace)
		return nil
	}

	fmt.Fprintf(os.Stderr, "\n🛡  Generated %d NetworkPolicies for unprotected pods:\n\n", len(policies))

	switch genOutputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(policies)
	default:
		for i, pol := range policies {
			fmt.Fprintf(os.Stderr, "  %d. %s (score %d → ~%d after policy)\n", i+1, pol.PodName, pol.RiskBefore, pol.RiskAfter)
			fmt.Fprintln(os.Stdout, pol.YAML)
			if i < len(policies)-1 {
				fmt.Fprintln(os.Stdout, "---")
			}
		}
		return nil
	}
}
