package netpol

import (
	"fmt"
	"strings"

	"github.com/plexar-io/plexar/internal/types"
)

// GeneratedPolicy is a recommended NetworkPolicy for a pod
type GeneratedPolicy struct {
	PodName    string `json:"podName"`
	Namespace  string `json:"namespace"`
	YAML       string `json:"yaml"`
	Priority   string `json:"priority"`
	Reason     string `json:"reason"`
	RiskBefore int    `json:"riskBefore"`
	RiskAfter  int    `json:"riskAfter"`
}

// Generate creates NetworkPolicy suggestions for pods without policies,
// prioritized by blast radius score (highest risk first)
func Generate(scores []types.PlexarScore, namespace string) []GeneratedPolicy {
	var policies []GeneratedPolicy

	for _, s := range scores {
		if s.Blast.HasNetworkPolicy {
			continue
		}

		// Estimate risk reduction
		riskAfter := s.Total - s.BlastScore - s.PolicyGapScore
		if riskAfter < 0 {
			riskAfter = 0
		}

		yaml := generateYAML(s, namespace)

		policies = append(policies, GeneratedPolicy{
			PodName:    s.PodName,
			Namespace:  namespace,
			YAML:       yaml,
			Priority:   s.Tier,
			Reason:     fmt.Sprintf("Score %d → ~%d after policy. Restricts access from %d services to %d configured targets.", s.Total, riskAfter, len(s.Blast.ReachableTargets), len(s.Blast.ConfiguredTargets)),
			RiskBefore: s.Total,
			RiskAfter:  riskAfter,
		})
	}

	return policies
}

func generateYAML(s types.PlexarScore, namespace string) string {
	svcName := shortName(s.PodName)

	var egressRules strings.Builder
	for _, target := range s.Blast.ConfiguredTargets {
		egressRules.WriteString(fmt.Sprintf(`    - to:
        - podSelector:
            matchLabels:
              app: %s
`, target))
	}

	// Add DNS egress
	egressRules.WriteString(`    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
`)

	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s-restrict
  namespace: %s
  labels:
    app.kubernetes.io/managed-by: plexar
    plexar.io/generated: "true"
spec:
  podSelector:
    matchLabels:
      app: %s
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector: {}
  egress:
%s`, svcName, namespace, svcName, egressRules.String())
}

func shortName(podName string) string {
	parts := strings.Split(podName, "-")
	if len(parts) > 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return podName
}
