package scanner

import (
	"context"
	"fmt"
	"io"

	"github.com/plexar-security/plexar/internal/types"
	"github.com/plexar-security/plexar/pkg/k8s"
)

// VulnSource is the interface for pluggable vulnerability data backends.
// Implement this to bring your own scanner.
type VulnSource interface {
	// Name returns a human-readable name for this source (e.g. "trivy", "grype")
	Name() string

	// ScanNamespace returns per-pod vulnerability summaries for the given namespace.
	ScanNamespace(ctx context.Context, client *k8s.Client, namespace string) ([]types.VulnSummary, error)
}

// Supported vuln source names
const (
	SourceTrivy         = "trivy"
	SourceTrivyOperator = "trivy-operator"
	SourceNone          = "none"
)

// SourceOptions configures optional behavior for a VulnSource.
type SourceOptions struct {
	// Progress receives per-image status (Trivy backend only). Nil to suppress.
	Progress io.Writer
	// Fresh forces re-scan even if cache is valid (Trivy backend only).
	Fresh bool
}

// NewSource creates a VulnSource by name.
// "trivy"          — runs trivy binary as subprocess (default)
// "trivy-operator" — reads existing VulnerabilityReport CRDs
// "none"           — skip CVE scanning, score on blast radius only
func NewSource(name string, opts ...SourceOptions) (VulnSource, error) {
	var opt SourceOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	switch name {
	case SourceTrivy, "":
		return &TrivyScanner{Progress: opt.Progress, Fresh: opt.Fresh}, nil
	case SourceTrivyOperator:
		return &TrivyOperatorScanner{}, nil
	case SourceNone:
		return &NoopScanner{}, nil
	default:
		return nil, fmt.Errorf("unknown vuln source %q (supported: trivy, trivy-operator, none)", name)
	}
}
