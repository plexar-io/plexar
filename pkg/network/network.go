package network

import (
	"context"
	"fmt"
	"strings"

	"github.com/plexar-io/plexar/internal/types"
	"github.com/plexar-io/plexar/pkg/k8s"
	corev1 "k8s.io/api/core/v1"
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

	// Detect internet-exposed services via Ingress resources
	internetExposedSvcs := make(map[string]bool)
	ingresses, err := a.client.Clientset.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ing := range ingresses.Items {
			for _, rule := range ing.Spec.Rules {
				if rule.HTTP != nil {
					for _, path := range rule.HTTP.Paths {
						if path.Backend.Service != nil {
							internetExposedSvcs[path.Backend.Service.Name] = true
						}
					}
				}
			}
			if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
				internetExposedSvcs[ing.Spec.DefaultBackend.Service.Name] = true
			}
		}
	}

	// Detect LoadBalancer / NodePort services (also internet-reachable)
	for _, svc := range services.Items {
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer || svc.Spec.Type == corev1.ServiceTypeNodePort {
			internetExposedSvcs[svc.Name] = true
		}
	}

	// Map service names → pod names via label selectors
	internetExposedPods := make(map[string]bool)
	for _, svc := range services.Items {
		if !internetExposedSvcs[svc.Name] {
			continue
		}
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		for _, pod := range pods.Items {
			if matchesLabels(pod.Labels, svc.Spec.Selector) {
				internetExposedPods[pod.Name] = true
			}
		}
	}

	// Load ConfigMaps for target inference
	configMaps := make(map[string]map[string]string) // name → data
	cmList, cmErr := a.client.Clientset.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if cmErr == nil {
		for _, cm := range cmList.Items {
			configMaps[cm.Name] = cm.Data
		}
	}

	// Parse NetworkPolicy egress rules: pod label set → allowed service names
	type egressRule struct {
		podSelector map[string]string
		allowedSvcs []string
	}
	var egressRules []egressRule
	for _, np := range netpols.Items {
		sel := np.Spec.PodSelector.MatchLabels
		var allowed []string
		for _, egress := range np.Spec.Egress {
			for _, to := range egress.To {
				if to.PodSelector != nil {
					// Find services whose selector matches the egress destination
					for _, svc := range services.Items {
						if matchesLabels(svc.Spec.Selector, to.PodSelector.MatchLabels) {
							allowed = appendUnique(allowed, svc.Name)
						}
					}
				}
			}
		}
		if len(allowed) > 0 {
			egressRules = append(egressRules, egressRule{podSelector: sel, allowedSvcs: allowed})
		}
	}

	// Cross-namespace services: for unrestricted pods, they can also reach other namespaces
	var crossNsSvcNames []string
	allNsList, nsErr := a.client.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if nsErr == nil {
		systemNS := map[string]bool{"kube-system": true, "kube-public": true, "kube-node-lease": true}
		for _, ns := range allNsList.Items {
			if ns.Name == namespace || systemNS[ns.Name] {
				continue
			}
			otherSvcs, svcErr := a.client.Clientset.CoreV1().Services(ns.Name).List(ctx, metav1.ListOptions{})
			if svcErr == nil {
				for _, svc := range otherSvcs.Items {
					if svc.Name != "kubernetes" {
						crossNsSvcNames = append(crossNsSvcNames, svc.Name+"."+ns.Name)
					}
				}
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

			// Also scan ConfigMaps mounted by this container
			for _, vm := range container.VolumeMounts {
				for _, vol := range pod.Spec.Volumes {
					if vol.Name == vm.Name && vol.ConfigMap != nil {
						if cmData, ok := configMaps[vol.ConfigMap.Name]; ok {
							for _, val := range cmData {
								valLower := strings.ToLower(val)
								for _, svc := range svcNames {
									if strings.Contains(valLower, svc) {
										configuredTargets = appendUnique(configuredTargets, svc)
									}
								}
							}
						}
					}
				}
			}

			// Scan envFrom ConfigMapRef
			for _, envFrom := range container.EnvFrom {
				if envFrom.ConfigMapRef != nil {
					if cmData, ok := configMaps[envFrom.ConfigMapRef.Name]; ok {
						for _, val := range cmData {
							valLower := strings.ToLower(val)
							for _, svc := range svcNames {
								if strings.Contains(valLower, svc) {
									configuredTargets = appendUnique(configuredTargets, svc)
								}
							}
						}
					}
				}
			}
		}

		// Add targets from NetworkPolicy egress rules
		for _, er := range egressRules {
			if matchesLabels(pod.Labels, er.podSelector) {
				for _, svc := range er.allowedSvcs {
					configuredTargets = appendUnique(configuredTargets, svc)
				}
			}
		}

		// Determine reachable targets
		var reachableTargets []string
		internetAccess := internetExposedPods[pod.Name]
		if hasPol {
			// With NetworkPolicy: only configured targets are reachable (simplified)
			reachableTargets = configuredTargets
		} else {
			// Without NetworkPolicy: can reach everything in this namespace
			for _, svc := range svcNames {
				if svc != pod.Name {
					reachableTargets = append(reachableTargets, svc)
				}
			}
			// Also reachable: services in other namespaces
			reachableTargets = append(reachableTargets, crossNsSvcNames...)
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

// AnalyzeNamespaceWithFlows builds blast radius from observed Hubble flows
// instead of inferred reachability. This provides ground-truth network
// connectivity based on actual traffic patterns.
func (a *Analyzer) AnalyzeNamespaceWithFlows(ctx context.Context, namespace string, flows []types.ObservedFlow) ([]types.BlastRadius, int, error) {
	// List all pods
	pods, err := a.client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list pods: %w", err)
	}

	// NetworkPolicy count (still needed for scoring)
	netpols, err := a.client.Clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list NetworkPolicies: %w", err)
	}
	netPolCount := len(netpols.Items)

	// Build covered pods set (for HasNetworkPolicy)
	coveredPods := make(map[string]bool)
	for _, np := range netpols.Items {
		sel := np.Spec.PodSelector.MatchLabels
		for _, pod := range pods.Items {
			if matchesLabels(pod.Labels, sel) {
				coveredPods[pod.Name] = true
			}
		}
	}

	// Build flow index: srcPod -> []ObservedFlow
	flowIndex := make(map[string][]types.ObservedFlow)
	for _, f := range flows {
		if f.SrcPod != "" {
			flowIndex[f.SrcPod] = append(flowIndex[f.SrcPod], f)
		}
	}

	var results []types.BlastRadius
	for _, pod := range pods.Items {
		podFlows := flowIndex[pod.Name]

		// Build reachable targets from observed flows (forwarded only)
		reachableSet := make(map[string]bool)
		hasExternal := false
		for _, f := range podFlows {
			if f.Verdict != "" && f.Verdict != "FORWARDED" {
				continue
			}
			if f.DstPod != "" && f.DstPod != pod.Name {
				reachableSet[f.DstPod] = true
			}
			if f.DstPod == "" && f.DstIP != "" {
				hasExternal = true
			}
		}

		var reachableTargets []string
		for t := range reachableSet {
			reachableTargets = append(reachableTargets, t)
		}

		// Detect data store access from observed targets
		dataStores := detectDataStores(reachableTargets)

		results = append(results, types.BlastRadius{
			PodName:            pod.Name,
			ReachableTargets:   reachableTargets,
			HasNetworkPolicy:   coveredPods[pod.Name],
			UnrestrictedEgress: !coveredPods[pod.Name],
			InternetAccess:     hasExternal,
			DataStoreAccess:    dataStores,
			ObservedFlows:      podFlows,
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
