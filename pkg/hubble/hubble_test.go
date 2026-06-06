package hubble

import (
	"context"
	"testing"
	"time"

	"github.com/plexar-io/plexar/internal/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAggregate(t *testing.T) {
	now := time.Now()
	flows := []types.ObservedFlow{
		{SrcPod: "web", DstPod: "api", Port: 8080, Protocol: "TCP", Verdict: "FORWARDED", RequestCount: 1, ByteCount: 512, LastSeen: now},
		{SrcPod: "web", DstPod: "api", Port: 8080, Protocol: "TCP", Verdict: "FORWARDED", RequestCount: 1, ByteCount: 256, LastSeen: now.Add(-time.Minute)},
		{SrcPod: "web", DstPod: "db", Port: 5432, Protocol: "TCP", Verdict: "FORWARDED", RequestCount: 1, ByteCount: 1024, LastSeen: now},
		{SrcPod: "api", DstPod: "db", Port: 5432, Protocol: "TCP", L7Protocol: "HTTP", Verdict: "FORWARDED", RequestCount: 1, ByteCount: 2048, LastSeen: now},
		{SrcPod: "web", DstPod: "api", Port: 8080, Protocol: "TCP", Verdict: "DROPPED", RequestCount: 1, ByteCount: 100, LastSeen: now},
	}

	summaries := Aggregate(flows)

	if len(summaries) != 3 {
		t.Fatalf("Expected 3 summaries, got %d", len(summaries))
	}

	// Find web->api summary
	var webApi *types.FlowSummary
	for i := range summaries {
		if summaries[i].SrcPod == "web" && summaries[i].DstPod == "api" {
			webApi = &summaries[i]
			break
		}
	}
	if webApi == nil {
		t.Fatal("Expected web->api summary")
	}

	if webApi.TotalReqs != 2 {
		t.Errorf("Expected 2 requests for web->api, got %d", webApi.TotalReqs)
	}
	if webApi.TotalBytes != 768 { // 512 + 256 (DROPPED excluded)
		t.Errorf("Expected 768 bytes for web->api, got %d", webApi.TotalBytes)
	}
	if len(webApi.Ports) != 1 || webApi.Ports[0] != 8080 {
		t.Errorf("Expected [8080] ports, got %v", webApi.Ports)
	}
}

func TestAggregate_DroppedExcluded(t *testing.T) {
	flows := []types.ObservedFlow{
		{SrcPod: "web", DstPod: "secret-db", Port: 5432, Verdict: "DROPPED", RequestCount: 1},
	}

	summaries := Aggregate(flows)
	if len(summaries) != 0 {
		t.Errorf("Expected 0 summaries for DROPPED-only flows, got %d", len(summaries))
	}
}

func TestFlowsToReachableTargets(t *testing.T) {
	flows := []types.ObservedFlow{
		{SrcPod: "web", DstPod: "api", Verdict: "FORWARDED"},
		{SrcPod: "web", DstPod: "cache", Verdict: "FORWARDED"},
		{SrcPod: "web", DstPod: "api", Verdict: "FORWARDED"}, // duplicate
		{SrcPod: "web", DstPod: "db", Verdict: "DROPPED"},    // dropped
		{SrcPod: "api", DstPod: "db", Verdict: "FORWARDED"},  // different source
	}

	targets := FlowsToReachableTargets(flows, "web")

	if len(targets) != 2 {
		t.Fatalf("Expected 2 reachable targets, got %d: %v", len(targets), targets)
	}
	// Should be sorted
	if targets[0] != "api" || targets[1] != "cache" {
		t.Errorf("Expected [api, cache], got %v", targets)
	}
}

func TestHasExternalTraffic(t *testing.T) {
	flows := []types.ObservedFlow{
		{SrcPod: "web", DstPod: "api", Verdict: "FORWARDED"},
		{SrcPod: "web", DstPod: "", DstIP: "8.8.8.8", Verdict: "FORWARDED"},
		{SrcPod: "api", DstPod: "", DstIP: "1.1.1.1", Verdict: "FORWARDED"},
	}

	if !HasExternalTraffic(flows, "web") {
		t.Error("Expected external traffic for web")
	}
	if HasExternalTraffic(flows, "db") {
		t.Error("Expected no external traffic for db")
	}
}

func TestFilterByAge(t *testing.T) {
	now := time.Now()
	flows := []types.ObservedFlow{
		{SrcPod: "web", DstPod: "api", LastSeen: now},
		{SrcPod: "web", DstPod: "old", LastSeen: now.Add(-2 * time.Hour)},
		{SrcPod: "web", DstPod: "recent", LastSeen: now.Add(-30 * time.Minute)},
	}

	result := FilterByAge(flows, time.Hour)

	if len(result) != 2 {
		t.Fatalf("Expected 2 flows within 1h, got %d", len(result))
	}
}

func TestProbe_ServiceFound(t *testing.T) {
	clientset := fake.NewSimpleClientset(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hubble-relay",
			Namespace: "kube-system",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "grpc", Port: 4245},
			},
		},
	})

	addr, err := Probe(context.Background(), clientset, "kube-system")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if addr == "" {
		t.Fatal("Expected non-empty address")
	}
	if addr != "hubble-relay.kube-system.svc.cluster.local:4245" {
		t.Errorf("Expected hubble-relay.kube-system.svc.cluster.local:4245, got %s", addr)
	}
}

func TestProbe_ServiceNotFound(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	addr, err := Probe(context.Background(), clientset, "kube-system")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if addr != "" {
		t.Errorf("Expected empty address when service not found, got %s", addr)
	}
}

func TestConvertRawFlow(t *testing.T) {
	rf := rawFlow{
		Time:    "2024-01-15T10:30:00Z",
		Verdict: "FORWARDED",
	}
	rf.Source.PodName = "web-pod"
	rf.Source.Namespace = "default"
	rf.Destination.PodName = "api-pod"
	rf.Destination.Namespace = "default"
	rf.Destination.Port = 8080
	rf.L4.Protocol = "TCP"

	flow := convertRawFlow(rf, "default")

	if flow.SrcPod != "web-pod" {
		t.Errorf("Expected SrcPod web-pod, got %s", flow.SrcPod)
	}
	if flow.DstPod != "api-pod" {
		t.Errorf("Expected DstPod api-pod, got %s", flow.DstPod)
	}
	if flow.Port != 8080 {
		t.Errorf("Expected Port 8080, got %d", flow.Port)
	}
	if flow.Verdict != "FORWARDED" {
		t.Errorf("Expected Verdict FORWARDED, got %s", flow.Verdict)
	}
}

func TestConvertRawFlow_FilteredByNamespace(t *testing.T) {
	rf := rawFlow{}
	rf.Source.PodName = "web"
	rf.Source.Namespace = "other-ns"
	rf.Destination.PodName = "api"
	rf.Destination.Namespace = "other-ns"

	flow := convertRawFlow(rf, "default")

	// Both pods are in a different namespace, should return empty flow
	if flow.SrcPod != "" || flow.DstPod != "" {
		t.Error("Expected empty flow for pods outside target namespace")
	}
}
