package vanta

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/plexar-io/plexar/internal/types"
)

func mockRecord() *types.EvidenceRecord {
	return &types.EvidenceRecord{
		ID:              "rec-001",
		Timestamp:       time.Now(),
		ClusterName:     "test-cluster",
		Namespace:       "default",
		ClusterScore:    72,
		TotalPods:       5,
		NetworkPolicies: 2,
		Controls: []types.ControlEvidence{
			{Framework: "SOC 2", ControlID: "CC6.1", ControlName: "Logical Access", Status: "pass", Violations: 0, Evidence: "All pods use RBAC"},
			{Framework: "SOC 2", ControlID: "CC7.1", ControlName: "System Monitoring", Status: "fail", Violations: 3, Evidence: "3 pods missing probes"},
		},
		Summary: types.EvidenceSummary{
			CriticalPods:    1,
			HighPods:        2,
			UnprotectedPods: 1,
			CriticalCVEs:    5,
			ComplianceScore: 72,
		},
		PrevHash: "abc123",
		Hash:     "def456",
	}
}

func TestPushEvidence(t *testing.T) {
	var received vantaEvidence
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing or wrong auth header")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("missing content-type")
		}

		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "vanta-123"})
	}))
	defer server.Close()

	client := NewClient("test-token")
	client.SetBaseURL(server.URL)

	result, err := client.PushEvidence(mockRecord())
	if err != nil {
		t.Fatalf("PushEvidence failed: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.VantaID != "vanta-123" {
		t.Errorf("VantaID = %s, want vanta-123", result.VantaID)
	}
	if received.UniqueID != "rec-001" {
		t.Errorf("UniqueID = %s, want rec-001", received.UniqueID)
	}
	if len(received.Body.Controls) != 2 {
		t.Errorf("controls = %d, want 2", len(received.Body.Controls))
	}
	if received.Body.HashChain.RecordHash != "def456" {
		t.Errorf("hash = %s, want def456", received.Body.HashChain.RecordHash)
	}
}

func TestPushControls(t *testing.T) {
	var received vantaControlsPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewClient("test-token")
	client.SetBaseURL(server.URL)

	controls := []types.ControlEvidence{
		{Framework: "SOC 2", ControlID: "CC6.1", ControlName: "Logical Access", Status: "pass"},
		{Framework: "SOC 2", ControlID: "CC7.1", ControlName: "Monitoring", Status: "fail"},
		{Framework: "SOC 2", ControlID: "CC8.1", ControlName: "Change Mgmt", Status: "partial"},
	}

	result, err := client.PushControls(controls, "test-cluster")
	if err != nil {
		t.Fatalf("PushControls failed: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.ControlsPushed != 3 {
		t.Errorf("ControlsPushed = %d, want 3", result.ControlsPushed)
	}
	if received.IntegrationName != "plexar" {
		t.Errorf("IntegrationName = %s, want plexar", received.IntegrationName)
	}
	if len(received.Resources) != 3 {
		t.Fatalf("resources = %d, want 3", len(received.Resources))
	}
	if received.Resources[0].Status != "PASSING" {
		t.Errorf("pass → %s, want PASSING", received.Resources[0].Status)
	}
	if received.Resources[1].Status != "FAILING" {
		t.Errorf("fail → %s, want FAILING", received.Resources[1].Status)
	}
	if received.Resources[2].Status != "WARNING" {
		t.Errorf("partial → %s, want WARNING", received.Resources[2].Status)
	}
}

func TestPushEvidenceError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
	}))
	defer server.Close()

	client := NewClient("bad-token")
	client.SetBaseURL(server.URL)

	result, err := client.PushEvidence(mockRecord())
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if result.Success {
		t.Error("expected failure")
	}
	if result.StatusCode != 401 {
		t.Errorf("status = %d, want 401", result.StatusCode)
	}
}
