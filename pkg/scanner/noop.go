package scanner

import (
	"context"

	"github.com/plexar-security/plexar/internal/types"
	"github.com/plexar-security/plexar/pkg/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NoopScanner skips CVE scanning entirely.
// Plexar will still score pods on blast radius, permissions, and policy gaps.
// Use this when you don't have a vulnerability scanner or want network-only analysis.
type NoopScanner struct{}

func (n *NoopScanner) Name() string { return "none" }

// ScanNamespace returns an empty VulnSummary for each pod (zero CVEs).
// This ensures blast radius, permissions, and policy gap scoring still work.
func (n *NoopScanner) ScanNamespace(ctx context.Context, client *k8s.Client, namespace string) ([]types.VulnSummary, error) {
	pods, err := client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var results []types.VulnSummary
	for _, pod := range pods.Items {
		imageName := ""
		if len(pod.Spec.Containers) > 0 {
			imageName = pod.Spec.Containers[0].Image
		}
		results = append(results, types.VulnSummary{
			PodName:   pod.Name,
			ImageName: imageName,
		})
	}

	return results, nil
}
