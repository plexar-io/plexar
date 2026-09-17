package preflight

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/plexar-io/plexar/pkg/k8s"
	"github.com/plexar-io/plexar/pkg/scanner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CheckResult captures a single preflight check outcome
type CheckResult struct {
	Name    string
	Passed  bool
	Warning bool // non-fatal: printed as a warning, does not block the scan
	Message string
}

// Run executes all preflight checks and returns any failures as a user-friendly error.
// Returns nil if all checks pass.
//
// opts[0] = vuln source (trivy, trivy-operator, none); opts[1] = image source
// (auto, crio, containerd, docker).
func Run(kubeconfig, namespace string, opts ...string) error {
	vulnSrc, imageSrc := "", ""
	if len(opts) > 0 {
		vulnSrc = opts[0]
	}
	if len(opts) > 1 {
		imageSrc = opts[1]
	}
	client, err := k8s.NewClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("cannot connect to Kubernetes cluster.\n\n  Possible causes:\n  • No kubeconfig found (checked ~/.kube/config)\n  • Cluster is unreachable\n  • Context is invalid\n\n  Fix: ensure kubectl get nodes works, then retry.\n\n  Original error: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var failures []CheckResult

	// Check 1: Namespace exists and has pods
	nsCheck := checkNamespace(ctx, client, namespace)
	if !nsCheck.Passed {
		failures = append(failures, nsCheck)
	}

	// Check 2+3: Trivy Operator CRDs (only for trivy-operator source)
	if vulnSrc == "trivy-operator" || vulnSrc == "" {
		trivyCheck := checkTrivyOperator(ctx, client)
		if !trivyCheck.Passed {
			failures = append(failures, trivyCheck)
		}

		if trivyCheck.Passed {
			vulnCheck := checkVulnReports(ctx, client, namespace)
			if !vulnCheck.Passed {
				failures = append(failures, vulnCheck)
			}
		}
	}

	// Check: Trivy subprocess tooling — only for the default binary source.
	// Catches the air-gapped/CRI-O gotchas (missing trivy, stale/absent offline
	// DB, missing crictl/skopeo) that otherwise surface as silent empty results.
	if vulnSrc == "trivy" {
		for _, c := range checkTrivyTooling(imageSrc) {
			if c.Passed {
				continue
			}
			if c.Warning {
				fmt.Fprintf(os.Stderr, "  ⚠  %s\n", c.Message)
			} else {
				failures = append(failures, c)
			}
		}
	}

	// Check 4: RBAC permissions to read required resources (warning only —
	// the scan degrades gracefully when NetworkPolicies/RBAC are inaccessible)
	rbacCheck := checkRBACPermissions(ctx, client, namespace)
	if !rbacCheck.Passed {
		fmt.Fprintf(os.Stderr, "  ⚠  %s (will scan with reduced data)\n", rbacCheck.Message)
	}

	if len(failures) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString("\n⚠  Preflight checks failed:\n\n")
	for i, f := range failures {
		sb.WriteString(fmt.Sprintf("  %d. %s\n     %s\n\n", i+1, f.Name, f.Message))
	}
	sb.WriteString("Fix the above issues and retry. Use --vuln-source=none to skip Trivy checks.\n")
	return fmt.Errorf("%s", sb.String())
}

func checkNamespace(ctx context.Context, client *k8s.Client, namespace string) CheckResult {
	result := CheckResult{Name: "Namespace check"}

	_, err := client.Clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		result.Message = fmt.Sprintf("Namespace '%s' not found.\n     Fix: check the namespace name or create it with: kubectl create namespace %s", namespace, namespace)
		return result
	}

	_, err = client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		result.Message = fmt.Sprintf("Cannot list pods in namespace '%s'. Check RBAC permissions.", namespace)
		return result
	}

	// Empty namespaces are fine — the scan will just produce empty results
	result.Passed = true
	return result
}

func checkTrivyOperator(ctx context.Context, client *k8s.Client) CheckResult {
	result := CheckResult{Name: "Trivy Operator check"}

	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	_, err := client.DynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		result.Message = "Trivy Operator not detected (VulnerabilityReport CRD missing).\n     Install: helm install trivy-operator aquasecurity/trivy-operator -n trivy-system --create-namespace\n     Or skip: use --vuln-source=none to scan without CVE data"
		return result
	}

	result.Passed = true
	return result
}

func checkVulnReports(ctx context.Context, client *k8s.Client, namespace string) CheckResult {
	result := CheckResult{Name: "VulnerabilityReports check"}

	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	reports, err := client.DynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		result.Message = fmt.Sprintf("Cannot read VulnerabilityReports in namespace '%s'.\n     The Trivy Operator may still be scanning. Wait a few minutes and retry.\n     Check: kubectl get vulnerabilityreports -n %s", namespace, namespace)
		return result
	}

	if len(reports.Items) == 0 {
		result.Message = fmt.Sprintf("No VulnerabilityReports found in namespace '%s'.\n     The Trivy Operator may still be scanning. Wait a few minutes and retry.\n     Check: kubectl get vulnerabilityreports -n %s", namespace, namespace)
		return result
	}

	result.Passed = true
	return result
}

// checkTrivyTooling validates the local environment for the trivy binary scan
// path: the binary itself, an offline-usable vulnerability DB, and (for CRI-O
// nodes) the crictl/skopeo tools needed to export images. Returns a mix of
// hard failures and non-fatal warnings.
func checkTrivyTooling(imageSrc string) []CheckResult {
	var results []CheckResult

	// 1. Trivy binary — check PATH/common locations, then auto-download if missing
	trivyPath, err := scanner.FindTrivy()
	if err != nil {
		// Attempt auto-download before failing the preflight
		trivyPath, err = scanner.EnsureTrivy(os.Stderr)
		if err != nil {
			results = append(results, CheckResult{
				Name: "Trivy binary",
				Message: "trivy binary not found and auto-download failed: " + err.Error() + "\n" +
					"     Install manually:\n" +
					"       macOS:  brew install trivy\n" +
					"       Linux:  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin\n" +
					"       Or set: TRIVY_PATH=/path/to/trivy\n" +
					"     Skip:    --vuln-source=none (score on blast radius + permissions only)",
			})
			return results // nothing else is meaningful without trivy
		}
	}
	results = append(results, CheckResult{Name: "Trivy binary", Passed: true, Message: "found at " + trivyPath})

	// 2. Trivy vulnerability DB (offline-safe presence + freshness)
	dbPath, updatedAt, dberr := scanner.TrivyDBInfo()
	if dberr != nil {
		results = append(results, CheckResult{
			Name:    "Trivy vulnerability DB",
			Message: fmt.Sprintf("Trivy DB %v.\n     The CRI-O/air-gapped scan path uses --offline-scan and will NOT auto-download it — scans would return no CVEs.\n     Fix: on an internet-connected host run 'trivy image --download-db-only',\n     then copy the cache to this host:\n       macOS: ~/Library/Caches/trivy\n       Linux: ~/.cache/trivy\n     Or set TRIVY_CACHE_DIR to point at the DB location.", dberr),
		})
	} else if age := time.Since(updatedAt); age > 14*24*time.Hour {
		results = append(results, CheckResult{
			Name:    "Trivy vulnerability DB",
			Warning: true,
			Message: fmt.Sprintf("Trivy DB is %d days old (%s) — results may miss recent CVEs. Refresh with 'trivy image --download-db-only'.", int(age.Hours()/24), dbPath),
		})
	} else {
		results = append(results, CheckResult{Name: "Trivy vulnerability DB", Passed: true})
	}

	// 3. Image runtime / CRI-O tooling
	detected := imageSrc
	if detected == "" || detected == scanner.ImageSourceAuto {
		detected = scanner.DetectImageSource()
	}
	switch detected {
	case scanner.ImageSourceCRIO:
		if missing := missingTools("crictl", "skopeo"); len(missing) > 0 {
			results = append(results, CheckResult{
				Name:    "CRI-O tooling",
				Message: fmt.Sprintf("CRI-O runtime selected but missing required tool(s): %s.\n     These export container images from CRI-O storage for scanning.\n     Fix: install %s on this node.", strings.Join(missing, ", "), strings.Join(missing, ", ")),
			})
		} else {
			results = append(results, CheckResult{Name: "CRI-O tooling", Passed: true, Message: "crictl + skopeo present"})
		}
	case scanner.ImageSourceContainerd, scanner.ImageSourceDocker:
		results = append(results, CheckResult{Name: "Container runtime", Passed: true, Message: detected + " detected"})
	default:
		// Auto-detect found no runtime. If we're sitting on a CRI-O node, the
		// most likely cause is missing crictl/skopeo — surface that as a hard
		// failure rather than a vague warning.
		if _, statErr := os.Stat("/run/crio/crio.sock"); statErr == nil {
			missing := missingTools("crictl", "skopeo")
			results = append(results, CheckResult{
				Name:    "CRI-O tooling",
				Message: fmt.Sprintf("CRI-O socket found at /run/crio/crio.sock but tool(s) missing: %s.\n     Install them and re-run with --image-source crio.", strings.Join(missing, ", ")),
			})
		} else if imageSrc != "" && imageSrc != scanner.ImageSourceAuto {
			results = append(results, CheckResult{
				Name:    "Container runtime",
				Message: fmt.Sprintf("--image-source=%s requested but its runtime was not detected on this host.\n     Run Plexar on a cluster node, or omit --image-source to let Trivy pull images from the registry.", imageSrc),
			})
		} else {
			results = append(results, CheckResult{
				Name:    "Container runtime",
				Warning: true,
				Message: "No local container runtime detected (CRI-O/containerd/docker). Trivy will pull images from the registry — ensure this host can reach it, or run Plexar on a node for local image export.",
			})
		}
	}

	return results
}

// missingTools returns the subset of the given binaries not found in PATH.
func missingTools(tools ...string) []string {
	var missing []string
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	return missing
}

func checkRBACPermissions(ctx context.Context, client *k8s.Client, namespace string) CheckResult {
	result := CheckResult{Name: "RBAC permissions check"}

	// Try to list NetworkPolicies
	_, err := client.Clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		result.Message = fmt.Sprintf("Cannot read NetworkPolicies in namespace '%s'.\n     Your ServiceAccount needs: get, list on networkpolicies.networking.k8s.io\n     Fix: grant additional RBAC permissions to the Plexar ServiceAccount", namespace)
		return result
	}

	// Try to list RoleBindings
	_, err = client.Clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		result.Message = fmt.Sprintf("Cannot read RoleBindings in namespace '%s'.\n     Your ServiceAccount needs: get, list on rolebindings.rbac.authorization.k8s.io\n     Fix: grant additional RBAC permissions to the Plexar ServiceAccount", namespace)
		return result
	}

	result.Passed = true
	return result
}
