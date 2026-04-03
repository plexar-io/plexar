package classifier

import (
	"testing"

	"github.com/plexar-security/plexar/internal/types"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name       string
		podName    string
		imageName  string
		wantClass  string
		wantMinMul float64
	}{
		{"postgres image", "my-db-pod-abc-123", "postgres:15", "database", 1.3},
		{"redis image", "session-cache-abc-123", "redis:7.0", "cache", 1.2},
		{"nginx image", "api-gateway-abc-123", "nginx:1.25", "api-gateway", 1.2},
		{"elasticsearch image", "search-svc-abc-123", "elasticsearch:8.0", "search-engine", 1.2},
		{"rabbitmq image", "broker-abc-123", "rabbitmq:3.12", "message-queue", 1.1},
		{"keycloak image", "sso-abc-123", "keycloak:22", "auth-service", 1.4},
		{"payment name", "payment-processor-abc-123", "openjdk:17", "payment", 1.4},
		{"vault image", "secret-mgr-abc-123", "vault:1.15", "secret-manager", 1.4},
		{"pytorch image", "model-training-abc-123", "pytorch/pytorch:2.0", "ml-ai", 1.3},
		{"prometheus image", "monitoring-abc-123", "prom/prometheus:2.47", "monitoring", 0.8},
		{"generic app", "my-app-abc-123", "alpine:3.18", "application", 1.0},
		{"auth by name", "auth-service-abc-123", "golang:1.21", "auth-service", 1.4},
		{"jenkins image", "ci-runner-abc-123", "jenkins/jenkins:lts", "ci-cd", 1.3},
		{"minio image", "blob-store-abc-123", "minio/minio:latest", "storage", 1.2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := &types.PlexarScore{
				PodName:   tt.podName,
				ImageName: tt.imageName,
			}
			got := Classify(score)
			if got.Name != tt.wantClass {
				t.Errorf("Classify(%s, %s) = %s, want %s", tt.podName, tt.imageName, got.Name, tt.wantClass)
			}
			if got.RiskMultiplier < tt.wantMinMul {
				t.Errorf("Classify(%s, %s) multiplier = %.2f, want >= %.2f", tt.podName, tt.imageName, got.RiskMultiplier, tt.wantMinMul)
			}
		})
	}
}

func TestClassifyAll(t *testing.T) {
	scores := []types.PlexarScore{
		{PodName: "payment-svc-abc-123", ImageName: "openjdk:17", Total: 60, Tier: "high"},
		{PodName: "log-agent-abc-123", ImageName: "fluent/fluentd:v1.14", Total: 40, Tier: "medium"},
		{PodName: "pg-primary-abc-123", ImageName: "postgres:15", Total: 50, Tier: "high"},
		{PodName: "my-app-abc-123", ImageName: "alpine:3.18", Total: 20, Tier: "low"},
	}

	result := ClassifyAll(scores)

	// payment should be amplified
	if result[0].WorkloadClass != "Payment / Financial Service" {
		t.Errorf("payment class = %s, want Payment / Financial Service", result[0].WorkloadClass)
	}
	if result[0].Total <= 60 {
		t.Errorf("payment score should be amplified, got %d", result[0].Total)
	}
	if result[0].BaseScore != 60 {
		t.Errorf("payment base score should be 60, got %d", result[0].BaseScore)
	}

	// monitoring should be dampened
	if result[1].WorkloadClass != "Monitoring / Observability" {
		t.Errorf("fluentd class = %s, want Monitoring / Observability", result[1].WorkloadClass)
	}
	if result[1].Total >= 40 {
		t.Errorf("monitoring score should be dampened, got %d", result[1].Total)
	}

	// database should be amplified
	if result[2].WorkloadClass != "Database" {
		t.Errorf("postgres class = %s, want Database", result[2].WorkloadClass)
	}
	if result[2].Total <= 50 {
		t.Errorf("database score should be amplified, got %d", result[2].Total)
	}

	// generic app should stay the same
	if result[3].Total != 20 {
		t.Errorf("generic app score should be unchanged, got %d", result[3].Total)
	}
}

func TestClassifyAllCap100(t *testing.T) {
	scores := []types.PlexarScore{
		{PodName: "payment-svc-abc-123", ImageName: "openjdk:17", Total: 90, Tier: "critical"},
	}
	result := ClassifyAll(scores)
	if result[0].Total > 100 {
		t.Errorf("score should be capped at 100, got %d", result[0].Total)
	}
}

func TestTierRecalculation(t *testing.T) {
	scores := []types.PlexarScore{
		{PodName: "auth-svc-abc-123", ImageName: "keycloak:22", Total: 48, Tier: "medium"},
	}
	result := ClassifyAll(scores)
	// 48 * 1.5 = 72 → high
	if result[0].Tier != "high" {
		t.Errorf("tier should be recalculated to high, got %s (score=%d)", result[0].Tier, result[0].Total)
	}
}
