package network

import (
	"context"
	"fmt"
	"strings"

	"github.com/plexar-security/plexar/internal/types"
	"github.com/plexar-security/plexar/pkg/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Analyzer maps network reachability and blast radius per pod
type Analyzer struct {
	client *k8s.Client
}

// New creates an Analyzer
func New(client *k8s.Client) *Analyzer {
	return &Analyzer{client: client}
}

// AnalyzeNamespace determines blast radius for every pod in the namespace.
// Returns per-pod blast radius, total NetworkPolicy count, and any error.
func (a *Analyzer) AnalyzeNamespace(ctx context.Context, namespace string) ([]types.BlastRadius, int, error) {
	// List all pods
	pods, err := a.client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list pods: %w", err)
	}

	// List all services (for reachability targets)
	services, err := a.client.Clientset.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list services: %w", err)
	}

	var svcNames []string
	for _, svc := range services.Items {
		if svc.Name != "kubernetes" {
			svcNames = append(svcNames, svc.Name)
		}
	}

	// List NetworkPolicies
	netpols, err := a.client.Clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list NetworkPolicies: %w", err)
	}
	netPolCount := len(netpols.Items)

	// Build a set of pods that have at least one NetworkPolicy targeting them
	coveredPods := make(map[string]bool)
	for _, np := range netpols.Items {
		sel := np.Spec.PodSelector.MatchLabels
		for _, pod := range pods.Items {
			if matchesLabels(pod.Labels, sel) {
				coveredPods[pod.Name] = true
			}
		}
	}

	var results []types.BlastRadius
	for _, pod := range pods.Items {
		hasPol := coveredPods[pod.Name]

		// Infer configured targets from env vars
		var configuredTargets []string
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				for _, svc := range svcNames {
					if strings.Contains(strings.ToLower(env.Value), svc) {
						configuredTargets = appendUnique(configuredTargets, svc)
					}
				}
			}
		}

		// Determine reachable targets
		var reachableTargets []string
		internetAccess := false
		if hasPol {
			// With NetworkPolicy: only configured targets are reachable (simplified)
			reachableTargets = configuredTargets
		} else {
			// Without NetworkPolicy: can reach everything
			for _, svc := range svcNames {
				if svc != pod.Name {
					reachableTargets = append(reachableTargets, svc)
				}
			}
			internetAccess = true
		}

		// Detect data store access
		dataStores := detectDataStores(reachableTargets)

		results = append(results, types.BlastRadius{
			PodName:            pod.Name,
			ReachableTargets:   reachableTargets,
			ConfiguredTargets:  configuredTargets,
			HasNetworkPolicy:   hasPol,
			UnrestrictedEgress: !hasPol,
			InternetAccess:     internetAccess,
			DataStoreAccess:    dataStores,
		})
	}

	return results, netPolCount, nil
}

func matchesLabels(podLabels, selector map[string]string) bool {
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func detectDataStores(targets []string) []string {
	dataStoreKeywords := []string{"redis", "postgres", "mysql", "mongo", "elasticsearch", "kafka", "rabbitmq", "memcached", "cassandra"}
	var stores []string
	for _, t := range targets {
		tLower := strings.ToLower(t)
		for _, kw := range dataStoreKeywords {
			if strings.Contains(tLower, kw) {
				stores = append(stores, t)
				break
			}
		}
	}
	return stores
}
