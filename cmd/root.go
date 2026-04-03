package cmd

import (
	"fmt"
	"os"

	"github.com/plexar-security/plexar/pkg/scorer"
	"github.com/spf13/cobra"
)

var (
	kubeconfig    string
	namespace     string
	allNamespaces bool
	weightsFile   string
)

var rootCmd = &cobra.Command{
	Use:   "plexar",
	Short: "◈ Plexar — Kubernetes Security & Compliance",
	Long: `◈ Plexar — The security + compliance layer for Kubernetes workloads.

Plexar combines CVE severity with network reachability, runtime profiling,
and attack path analysis to show which vulnerable pods pose the greatest
risk to your cluster — and generates audit-ready compliance evidence.

Unlike traditional scanners that just list CVEs, Plexar shows the blast radius,
tags CVEs as "in use" at runtime, and maps findings to SOC 2, PCI DSS, EU CRA,
and more.`,
}

func Execute() error {
	if weightsFile != "" {
		if err := scorer.LoadWeights(weightsFile); err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Failed to load weights: %v\n", err)
		}
	}
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (default: in-cluster or ~/.kube/config)")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "default", "Target namespace(s) — comma-separated or 'all'")
	rootCmd.PersistentFlags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Scan all namespaces in the cluster")
	rootCmd.PersistentFlags().StringVar(&weightsFile, "weights", "", "Path to custom scoring weights JSON file")

	if ns := os.Getenv("PLEXAR_NAMESPACE"); ns != "" && namespace == "default" {
		namespace = ns
	}
	if kc := os.Getenv("KUBECONFIG"); kc != "" && kubeconfig == "" {
		kubeconfig = kc
	}

	fmt.Fprint(os.Stderr, "") // suppress unused import
}
