package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/plexar-security/plexar/internal/types"
	"github.com/plexar-security/plexar/pkg/k8s"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Auditor inspects Kubernetes RBAC resources for each pod
type Auditor struct {
	client *k8s.Client
}

// New creates an RBAC Auditor
func New(client *k8s.Client) *Auditor {
	return &Auditor{client: client}
}

// AuditNamespace inspects RBAC for every pod in the namespace
func (a *Auditor) AuditNamespace(ctx context.Context, namespace string) (*types.RBACAuditResult, error) {
	// List pods
	pods, err := a.client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Load all RBAC resources
	roleBindings, err := a.client.Clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list RoleBindings: %w", err)
	}

	clusterRoleBindings, err := a.client.Clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoleBindings: %w", err)
	}

	roles, err := a.client.Clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list Roles: %w", err)
	}

	clusterRoles, err := a.client.Clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoles: %w", err)
	}

	// Index roles by name for fast lookup
	roleMap := make(map[string]*rbacv1.Role)
	for i := range roles.Items {
		roleMap[roles.Items[i].Name] = &roles.Items[i]
	}
	crMap := make(map[string]*rbacv1.ClusterRole)
	for i := range clusterRoles.Items {
		crMap[clusterRoles.Items[i].Name] = &clusterRoles.Items[i]
	}

	// Build ServiceAccount -> bindings index
	saBindings := buildSABindingsIndex(namespace, roleBindings.Items, clusterRoleBindings.Items)

	result := &types.RBACAuditResult{
		Namespace: namespace,
		TotalPods: len(pods.Items),
	}

	for _, pod := range pods.Items {
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}

		finding := types.RBACFinding{
			PodName:            pod.Name,
			Namespace:          namespace,
			ServiceAccountName: sa,
		}

		// Find all bindings for this ServiceAccount
		bindings := saBindings[sa]
		for _, b := range bindings {
			var rules []rbacv1.PolicyRule
			ref := types.RBACRoleRef{
				BindingName: b.bindingName,
				BindingKind: b.bindingKind,
			}

			if b.roleKind == "Role" {
				if role, ok := roleMap[b.roleName]; ok {
					rules = role.Rules
					ref.Name = role.Name
					ref.Kind = "Role"
					ref.Namespace = namespace
				}
			} else if b.roleKind == "ClusterRole" {
				if cr, ok := crMap[b.roleName]; ok {
					rules = cr.Rules
					ref.Name = cr.Name
					ref.Kind = "ClusterRole"
				}
			}

			if ref.Name != "" {
				finding.Roles = append(finding.Roles, ref)
			}

			// Analyze each rule
			for _, rule := range rules {
				perm := analyzeRule(rule)
				finding.Permissions = append(finding.Permissions, perm)

				// Check for dangerous permissions
				if isClusterAdmin(b.roleName, rule) {
					finding.HasClusterAdmin = true
				}
				if hasWildcard(rule) {
					finding.HasWildcardAccess = true
				}
				if hasExec(rule) {
					finding.HasExecCapability = true
				}
				if hasSecretAccess(rule) {
					finding.HasSecretAccess = true
				}
				if hasDeleteAccess(rule) {
					finding.HasDeleteAccess = true
				}
				if hasCreatePods(rule) {
					finding.HasCreatePods = true
				}
				if hasDaemonSetAccess(rule) {
					finding.HasDaemonSetAccess = true
				}
				if hasNodeAccess(rule) {
					finding.HasNodeAccess = true
				}
				if hasEscalatePriv(rule) {
					finding.HasEscalatePriv = true
				}
			}
		}

		// Generate flags
		finding.Flags = generateFlags(finding)

		// Compute risk score
		finding.RiskScore = computeRBACRiskScore(finding)
		finding.RiskLevel = riskLevel(finding.RiskScore)

		result.Findings = append(result.Findings, finding)

		switch finding.RiskLevel {
		case "critical":
			result.CriticalCount++
		case "high":
			result.HighCount++
		}
	}

	return result, nil
}

// AuditFindingForPod returns the RBAC finding for a specific pod name
func FindingForPod(findings []types.RBACFinding, podName string) *types.RBACFinding {
	for i := range findings {
		if findings[i].PodName == podName {
			return &findings[i]
		}
	}
	return nil
}

// ── Binding index ──

type saBinding struct {
	roleName    string
	roleKind    string // "Role" or "ClusterRole"
	bindingName string
	bindingKind string // "RoleBinding" or "ClusterRoleBinding"
}

func buildSABindingsIndex(namespace string, rbs []rbacv1.RoleBinding, crbs []rbacv1.ClusterRoleBinding) map[string][]saBinding {
	index := make(map[string][]saBinding)

	for _, rb := range rbs {
		for _, subject := range rb.Subjects {
			if subject.Kind == "ServiceAccount" &&
				(subject.Namespace == "" || subject.Namespace == namespace) {
				index[subject.Name] = append(index[subject.Name], saBinding{
					roleName:    rb.RoleRef.Name,
					roleKind:    rb.RoleRef.Kind,
					bindingName: rb.Name,
					bindingKind: "RoleBinding",
				})
			}
		}
	}

	for _, crb := range crbs {
		for _, subject := range crb.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Namespace == namespace {
				index[subject.Name] = append(index[subject.Name], saBinding{
					roleName:    crb.RoleRef.Name,
					roleKind:    crb.RoleRef.Kind,
					bindingName: crb.Name,
					bindingKind: "ClusterRoleBinding",
				})
			}
		}
	}

	return index
}

// ── Rule analysis ──

func analyzeRule(rule rbacv1.PolicyRule) types.RBACPermission {
	perm := types.RBACPermission{
		Verbs:     rule.Verbs,
		Resources: rule.Resources,
	}

	if len(rule.APIGroups) > 0 {
		perm.APIGroup = strings.Join(rule.APIGroups, ", ")
	}

	perm.RiskLevel = ruleRiskLevel(rule)
	return perm
}

func ruleRiskLevel(rule rbacv1.PolicyRule) string {
	// Critical: wildcards on everything, cluster-admin equivalent
	if containsStr(rule.Verbs, "*") && containsStr(rule.Resources, "*") {
		return "critical"
	}

	// Critical: exec into pods
	if containsStr(rule.Resources, "pods/exec") {
		return "critical"
	}

	// Critical: secrets with write
	if containsStr(rule.Resources, "secrets") && hasWriteVerb(rule.Verbs) {
		return "critical"
	}

	// High: secrets read
	if containsStr(rule.Resources, "secrets") {
		return "high"
	}

	// High: daemonsets, deployments with create/delete
	if (containsStr(rule.Resources, "daemonsets") || containsStr(rule.Resources, "deployments")) &&
		hasWriteVerb(rule.Verbs) {
		return "high"
	}

	// High: nodes access
	if containsStr(rule.Resources, "nodes") {
		return "high"
	}

	// High: wildcard verbs on specific resources
	if containsStr(rule.Verbs, "*") {
		return "high"
	}

	// High: delete on pods
	if containsStr(rule.Resources, "pods") && containsStr(rule.Verbs, "delete") {
		return "high"
	}

	// Medium: create pods
	if containsStr(rule.Resources, "pods") && containsStr(rule.Verbs, "create") {
		return "medium"
	}

	// Medium: configmaps with write
	if containsStr(rule.Resources, "configmaps") && hasWriteVerb(rule.Verbs) {
		return "medium"
	}

	// Medium: services, endpoints write
	if (containsStr(rule.Resources, "services") || containsStr(rule.Resources, "endpoints")) &&
		hasWriteVerb(rule.Verbs) {
		return "medium"
	}

	// Low: read-only on most resources
	if isReadOnly(rule.Verbs) {
		return "low"
	}

	return "medium"
}

// ── Dangerous permission checks ──

func isClusterAdmin(roleName string, rule rbacv1.PolicyRule) bool {
	if roleName == "cluster-admin" {
		return true
	}
	return containsStr(rule.Verbs, "*") && containsStr(rule.Resources, "*") &&
		containsStr(rule.APIGroups, "*")
}

func hasWildcard(rule rbacv1.PolicyRule) bool {
	return containsStr(rule.Verbs, "*") || containsStr(rule.Resources, "*")
}

func hasExec(rule rbacv1.PolicyRule) bool {
	return containsStr(rule.Resources, "pods/exec")
}

func hasSecretAccess(rule rbacv1.PolicyRule) bool {
	return containsStr(rule.Resources, "secrets") || containsStr(rule.Resources, "*")
}

func hasDeleteAccess(rule rbacv1.PolicyRule) bool {
	return containsStr(rule.Verbs, "delete") || containsStr(rule.Verbs, "deletecollection") ||
		containsStr(rule.Verbs, "*")
}

func hasCreatePods(rule rbacv1.PolicyRule) bool {
	return (containsStr(rule.Resources, "pods") || containsStr(rule.Resources, "*")) &&
		(containsStr(rule.Verbs, "create") || containsStr(rule.Verbs, "*"))
}

func hasDaemonSetAccess(rule rbacv1.PolicyRule) bool {
	return (containsStr(rule.Resources, "daemonsets") || containsStr(rule.Resources, "*")) &&
		hasWriteVerb(rule.Verbs)
}

func hasNodeAccess(rule rbacv1.PolicyRule) bool {
	return containsStr(rule.Resources, "nodes") || containsStr(rule.Resources, "nodes/proxy")
}

func hasEscalatePriv(rule rbacv1.PolicyRule) bool {
	return containsStr(rule.Verbs, "escalate") || containsStr(rule.Verbs, "bind") ||
		containsStr(rule.Verbs, "impersonate")
}

// ── Risk scoring ──

func computeRBACRiskScore(f types.RBACFinding) int {
	score := 0

	if f.HasClusterAdmin {
		score += 50
	}
	if f.HasWildcardAccess {
		score += 25
	}
	if f.HasExecCapability {
		score += 20
	}
	if f.HasSecretAccess {
		score += 15
	}
	if f.HasDeleteAccess {
		score += 10
	}
	if f.HasCreatePods {
		score += 10
	}
	if f.HasDaemonSetAccess {
		score += 10
	}
	if f.HasNodeAccess {
		score += 10
	}
	if f.HasEscalatePriv {
		score += 15
	}

	// No roles at all = using default SA = low risk
	if len(f.Roles) == 0 {
		return 5
	}

	if score > 100 {
		score = 100
	}
	return score
}

func riskLevel(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// ── Flag generation ──

func generateFlags(f types.RBACFinding) []string {
	var flags []string
	if f.HasClusterAdmin {
		flags = append(flags, "CLUSTER-ADMIN: full cluster access")
	}
	if f.HasWildcardAccess && !f.HasClusterAdmin {
		flags = append(flags, "WILDCARD: broad resource or verb access")
	}
	if f.HasExecCapability {
		flags = append(flags, "EXEC: can exec into pods")
	}
	if f.HasSecretAccess {
		flags = append(flags, "SECRETS: can read/write secrets")
	}
	if f.HasDeleteAccess && !f.HasClusterAdmin {
		flags = append(flags, "DELETE: can delete resources")
	}
	if f.HasCreatePods && !f.HasClusterAdmin {
		flags = append(flags, "CREATE-PODS: can create pods (container escape path)")
	}
	if f.HasDaemonSetAccess {
		flags = append(flags, "DAEMONSETS: can deploy to all nodes")
	}
	if f.HasNodeAccess {
		flags = append(flags, "NODES: can access node-level resources")
	}
	if f.HasEscalatePriv {
		flags = append(flags, "ESCALATE: can escalate/bind/impersonate")
	}
	if len(f.Roles) == 0 {
		flags = append(flags, "DEFAULT-SA: using default ServiceAccount (no explicit roles)")
	}
	return flags
}

// ── Helpers ──

func containsStr(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func hasWriteVerb(verbs []string) bool {
	for _, v := range verbs {
		switch v {
		case "create", "update", "patch", "delete", "deletecollection", "*":
			return true
		}
	}
	return false
}

func isReadOnly(verbs []string) bool {
	for _, v := range verbs {
		switch v {
		case "get", "list", "watch":
			continue
		default:
			return false
		}
	}
	return true
}
