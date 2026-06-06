package preflight

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/plexar-io/plexar/pkg/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CheckResult captures a single preflight check outcome
type CheckResult struct {
	Name    string
	Passed  bool
	Message string
}

// Run executes all preflight checks and returns any failures as a user-friendly error.
// Returns nil if all checks pass.
func Run(kubeconfig, namespace string) error {
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

	// Check 2: Trivy Operator CRDs installed
	trivyCheck := checkTrivyOperator(ctx, client)
	if !trivyCheck.Passed {
		failures = append(failures, trivyCheck)
	}

	// Check 3: VulnerabilityReports exist in namespace
	if trivyCheck.Passed {
		vulnCheck := checkVulnReports(ctx, client, namespace)
		if !vulnCheck.Passed {
			failures = append(failures, vulnCheck)
		}
	}

	// Check 4: RBAC permissions to read required resources
	rbacCheck := checkRBACPermissions(ctx, client, namespace)
	if !rbacCheck.Passed {
		failures = append(failures, rbacCheck)
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

	pods, err := client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		result.Message = fmt.Sprintf("Cannot list pods in namespace '%s'. Check RBAC permissions.", namespace)
		return result
	}

	if len(pods.Items) == 0 {
		result.Message = fmt.Sprintf("Namespace '%s' has no pods. Deploy workloads first, then scan.", namespace)
		return result
	}

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
