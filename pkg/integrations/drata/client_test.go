package drata

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/plexar-security/plexar/internal/types"
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
			{Framework: "SOC 2", ControlID: "CC6.1", ControlName: "Logical Access", Status: "pass", Violations: 0},
			{Framework: "SOC 2", ControlID: "CC7.1", ControlName: "Monitoring", Status: "fail", Violations: 3},
		},
		Summary: types.EvidenceSummary{
			CriticalPods:    1,
			ComplianceScore: 72,
		},
		PrevHash: "abc123",
		Hash:     "def456",
	}
}

func TestPushEvidence(t *testing.T) {
	var received drataEvidence
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing or wrong auth header")
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": 42})
	}))
	defer server.Close()

	client := NewClient("test-key")
	client.SetBaseURL(server.URL)

	result, err := client.PushEvidence(mockRecord())
	if err != nil {
		t.Fatalf("PushEvidence failed: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.DrataID != "42" {
		t.Errorf("DrataID = %s, want 42", result.DrataID)
	}
	if received.Body.Source != "plexar" {
		t.Errorf("source = %s, want plexar", received.Body.Source)
	}
	if len(received.Body.Controls) != 2 {
		t.Errorf("controls = %d, want 2", len(received.Body.Controls))
	}
	if received.Body.Integrity.RecordHash != "def456" {
		t.Errorf("hash = %s, want def456", received.Body.Integrity.RecordHash)
	}
}

func TestPushControls(t *testing.T) {
	var received drataControlsPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient("test-key")
	client.SetBaseURL(server.URL)

	controls := []types.ControlEvidence{
		{Framework: "SOC 2", ControlID: "CC6.1", Status: "pass"},
		{Framework: "SOC 2", ControlID: "CC7.1", Status: "fail"},
		{Framework: "SOC 2", ControlID: "CC8.1", Status: "partial"},
	}

	result, err := client.PushControls(controls, "test-cluster")
	if err != nil {
		t.Fatalf("PushControls failed: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(received.Controls) != 3 {
		t.Fatalf("controls = %d, want 3", len(received.Controls))
	}
	if received.Controls[0].Status != "PASSED" {
		t.Errorf("pass → %s, want PASSED", received.Controls[0].Status)
	}
	if received.Controls[1].Status != "FAILED" {
		t.Errorf("fail → %s, want FAILED", received.Controls[1].Status)
	}
	if received.Controls[2].Status != "WARNING" {
		t.Errorf("partial → %s, want WARNING", received.Controls[2].Status)
	}
}

func TestPushEvidenceError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
	}))
	defer server.Close()

	client := NewClient("bad-key")
	client.SetBaseURL(server.URL)

	result, err := client.PushEvidence(mockRecord())
	if err == nil {
		t.Fatal("expected error for 403")
	}
	if result.Success {
		t.Error("expected failure")
	}
	if result.StatusCode != 403 {
		t.Errorf("status = %d, want 403", result.StatusCode)
	}
}
