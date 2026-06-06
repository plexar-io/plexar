package permissions

import (
	"context"
	"fmt"
	"strings"

	"github.com/plexar-io/plexar/internal/types"
	"github.com/plexar-io/plexar/pkg/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Analyzer inspects pod security context and RBAC
type Analyzer struct {
	client *k8s.Client
}

// New creates an Analyzer
func New(client *k8s.Client) *Analyzer {
	return &Analyzer{client: client}
}

// AnalyzeNamespace checks security context for all pods in the namespace
func (a *Analyzer) AnalyzeNamespace(ctx context.Context, namespace string) ([]types.PodPermissions, error) {
	pods, err := a.client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	var results []types.PodPermissions

	for _, pod := range pods.Items {
		perm := types.PodPermissions{
			PodName:            pod.Name,
			ServiceAccountName: pod.Spec.ServiceAccountName,
		}

		if pod.Spec.HostNetwork {
			perm.HostNetwork = true
		}

		for _, container := range pod.Spec.Containers {
			sc := container.SecurityContext
			if sc != nil {
				if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
					perm.RunAsRoot = true
				}
				if sc.Privileged != nil && *sc.Privileged {
					perm.Privileged = true
				}
				if sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem {
					perm.ReadOnlyRootFS = true
				}
				if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
					perm.AllowPrivilegeEsc = true
				}
			}

			// Check pod-level security context
			if pod.Spec.SecurityContext != nil {
				if pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
					perm.RunAsRoot = true
				}
				if pod.Spec.SecurityContext.RunAsNonRoot != nil && !*pod.Spec.SecurityContext.RunAsNonRoot {
					perm.RunAsRoot = true
				}
			}

			// Detect plaintext secrets in env vars
			secretKeywords := []string{"password", "secret", "token", "api_key", "apikey", "private_key"}
			for _, env := range container.Env {
				if env.ValueFrom != nil {
					continue // Using secret refs is OK
				}
				nameLower := strings.ToLower(env.Name)
				for _, kw := range secretKeywords {
					if strings.Contains(nameLower, kw) && env.Value != "" {
						perm.EnvSecrets = append(perm.EnvSecrets, env.Name)
						break
					}
				}
			}
		}

		results = append(results, perm)
	}

	return results, nil
}
