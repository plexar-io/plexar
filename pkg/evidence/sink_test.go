package evidence

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/plexar-security/plexar/internal/types"
)

func testRecord() *types.EvidenceRecord {
	return &types.EvidenceRecord{
		ID:              "test-record-001",
		Timestamp:       time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
		ClusterName:     "plexar-demo",
		Namespace:       "production",
		ClusterScore:    55,
		TotalPods:       16,
		NetworkPolicies: 5,
		Controls: []types.ControlEvidence{
			{Framework: "SOC 2", ControlID: "CC6.1", ControlName: "Network Isolation", Status: "partial", Violations: 3},
		},
		Summary: types.EvidenceSummary{
			CriticalPods:    2,
			HighPods:        4,
			UnprotectedPods: 10,
			CriticalCVEs:    8,
			ComplianceScore: 55,
		},
		PrevHash: "abc123",
		Hash:     "def456",
	}
}

func TestWebhookSink(t *testing.T) {
	var receivedBody []byte
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	sink, err := NewWebhookSink(server.URL, map[string]string{
		"Authorization": "Bearer test-token",
		"X-Custom":      "plexar",
	})
	if err != nil {
		t.Fatalf("NewWebhookSink failed: %v", err)
	}

	if sink.Name() != "webhook://"+server.URL {
		t.Errorf("unexpected name: %s", sink.Name())
	}

	record := testRecord()
	if err := sink.Push(record); err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	// Verify headers
	if receivedHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", receivedHeaders.Get("Content-Type"))
	}
	if receivedHeaders.Get("Authorization") != "Bearer test-token" {
		t.Errorf("expected Authorization header, got %s", receivedHeaders.Get("Authorization"))
	}
	if receivedHeaders.Get("X-Custom") != "plexar" {
		t.Errorf("expected X-Custom header, got %s", receivedHeaders.Get("X-Custom"))
	}

	// Verify body
	var payload struct {
		Event  string                `json:"event"`
		Record *types.EvidenceRecord `json:"record"`
	}
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if payload.Event != "evidence.recorded" {
		t.Errorf("expected event 'evidence.recorded', got %q", payload.Event)
	}
	if payload.Record.ID != "test-record-001" {
		t.Errorf("expected record ID 'test-record-001', got %q", payload.Record.ID)
	}
}

func TestWebhookSinkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"server error"}`))
	}))
	defer server.Close()

	sink, _ := NewWebhookSink(server.URL, nil)
	err := sink.Push(testRecord())
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestS3SinkCreation(t *testing.T) {
	_, err := NewS3Sink("", "bucket", "key", "secret")
	if err == nil {
		t.Error("expected error for empty endpoint")
	}

	_, err = NewS3Sink("localhost:9000", "", "key", "secret")
	if err == nil {
		t.Error("expected error for empty bucket")
	}

	sink, err := NewS3Sink("localhost:9000", "plexar-evidence", "minioadmin", "minioadmin123")
	if err != nil {
		t.Fatalf("NewS3Sink failed: %v", err)
	}
	if sink.Name() != "s3://localhost:9000/plexar-evidence" {
		t.Errorf("unexpected name: %s", sink.Name())
	}
}

func TestS3SinkPush(t *testing.T) {
	var receivedPath string
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Extract host:port from test server URL
	endpoint := server.URL[7:] // strip "http://"

	sink, err := NewS3Sink(endpoint, "plexar-evidence", "minioadmin", "minioadmin123")
	if err != nil {
		t.Fatalf("NewS3Sink failed: %v", err)
	}

	record := testRecord()
	if err := sink.Push(record); err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	// Verify path format: /bucket/YYYY/MM/DD/scan-{id}.json
	expectedPath := "/plexar-evidence/2026/04/02/scan-test-record-001.json"
	if receivedPath != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, receivedPath)
	}

	// Verify body is valid JSON
	var rec types.EvidenceRecord
	if err := json.Unmarshal(receivedBody, &rec); err != nil {
		t.Fatalf("failed to unmarshal uploaded JSON: %v", err)
	}
	if rec.ID != "test-record-001" {
		t.Errorf("expected record ID 'test-record-001', got %q", rec.ID)
	}
}

func TestSinkManager(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr := NewSinkManager()
	if mgr.HasSinks() {
		t.Error("expected no sinks initially")
	}

	sink1, _ := NewWebhookSink(server.URL+"/hook1", nil)
	sink2, _ := NewWebhookSink(server.URL+"/hook2", nil)
	mgr.Add(sink1)
	mgr.Add(sink2)

	if !mgr.HasSinks() {
		t.Error("expected sinks after Add")
	}

	errs := mgr.PushAll(testRecord())
	if len(errs) > 0 {
		t.Errorf("expected no errors, got %v", errs)
	}

	if callCount != 2 {
		t.Errorf("expected 2 webhook calls, got %d", callCount)
	}

	log := mgr.Log(10)
	if len(log) != 2 {
		t.Errorf("expected 2 log entries, got %d", len(log))
	}
	for _, entry := range log {
		if !entry.Success {
			t.Errorf("expected success for %s", entry.SinkName)
		}
	}
}

func TestParseSinkDSN(t *testing.T) {
	tests := []struct {
		dsn      string
		wantType string
		wantErr  bool
	}{
		{"s3://minioadmin:minioadmin123@localhost:9000/plexar-evidence", "s3", false},
		{"webhook://https://example.com/hook", "webhook", false},
		{"webhook://https://example.com/hook?header=Authorization:Bearer+token", "webhook", false},
		{"unknown://foo", "", true},
	}

	for _, tt := range tests {
		cfg, err := ParseSinkDSN(tt.dsn)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseSinkDSN(%q) expected error", tt.dsn)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSinkDSN(%q) unexpected error: %v", tt.dsn, err)
			continue
		}
		if cfg.Type != tt.wantType {
			t.Errorf("ParseSinkDSN(%q) type = %q, want %q", tt.dsn, cfg.Type, tt.wantType)
		}
	}
}
