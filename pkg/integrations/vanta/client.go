package vanta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/plexar-io/plexar/internal/types"
)

const (
	defaultBaseURL = "https://api.vanta.com"
	apiVersion     = "v1"
)

// Client interacts with the Vanta API to push compliance evidence
type Client struct {
	apiToken   string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a Vanta API client
func NewClient(apiToken string) *Client {
	return &Client{
		apiToken:   apiToken,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// SetBaseURL overrides the default Vanta API URL (for testing)
func (c *Client) SetBaseURL(url string) {
	c.baseURL = url
}

// PushEvidence sends a compliance evidence record to Vanta
func (c *Client) PushEvidence(record *types.EvidenceRecord) (*PushResult, error) {
	evidence := mapToVantaEvidence(record)

	body, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}

	url := fmt.Sprintf("%s/%s/resources/evidence", c.baseURL, apiVersion)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("User-Agent", "plexar-io/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vanta API request failed: %w", err)
	}
	defer resp.Body.Close()

	result := &PushResult{
		StatusCode: resp.StatusCode,
		Timestamp:  time.Now(),
		RecordID:   record.ID,
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errBody map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		result.Error = fmt.Sprintf("vanta returned %d: %v", resp.StatusCode, errBody)
		return result, fmt.Errorf("%s", result.Error)
	}

	var respBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err == nil {
		if id, ok := respBody["id"].(string); ok {
			result.VantaID = id
		}
	}

	result.Success = true
	return result, nil
}

// PushControls sends SOC 2 control status to Vanta's custom controls API
func (c *Client) PushControls(controls []types.ControlEvidence, clusterName string) (*PushResult, error) {
	payload := mapToVantaControls(controls, clusterName)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal controls: %w", err)
	}

	url := fmt.Sprintf("%s/%s/resources/controls", c.baseURL, apiVersion)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("User-Agent", "plexar-io/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vanta controls API request failed: %w", err)
	}
	defer resp.Body.Close()

	result := &PushResult{
		StatusCode: resp.StatusCode,
		Timestamp:  time.Now(),
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		result.Error = fmt.Sprintf("vanta controls API returned %d", resp.StatusCode)
		return result, fmt.Errorf("%s", result.Error)
	}

	result.Success = true
	result.ControlsPushed = len(controls)
	return result, nil
}

// PushResult captures the outcome of an evidence push
type PushResult struct {
	Success        bool      `json:"success"`
	StatusCode     int       `json:"statusCode"`
	Timestamp      time.Time `json:"timestamp"`
	RecordID       string    `json:"recordId,omitempty"`
	VantaID        string    `json:"vantaId,omitempty"`
	ControlsPushed int       `json:"controlsPushed,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// ── Vanta API payload types ──

type vantaEvidence struct {
	DisplayName string            `json:"displayName"`
	Description string            `json:"description"`
	ExternalURL string            `json:"externalUrl,omitempty"`
	Body        vantaEvidenceBody `json:"body"`
	UniqueID    string            `json:"uniqueId"`
}

type vantaEvidenceBody struct {
	ClusterName     string                `json:"clusterName"`
	Namespace       string                `json:"namespace"`
	ScanTimestamp   time.Time             `json:"scanTimestamp"`
	ClusterScore    int                   `json:"clusterScore"`
	TotalPods       int                   `json:"totalPods"`
	NetworkPolicies int                   `json:"networkPolicies"`
	Summary         types.EvidenceSummary `json:"summary"`
	Controls        []vantaControl        `json:"controls"`
	HashChain       vantaHashChain        `json:"hashChain"`
}

type vantaControl struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"controlId"`
	ControlName string `json:"controlName"`
	Status      string `json:"status"`
	Violations  int    `json:"violations"`
	Evidence    string `json:"evidence"`
}

type vantaHashChain struct {
	RecordHash   string `json:"recordHash"`
	PreviousHash string `json:"previousHash"`
}

type vantaControlsPayload struct {
	IntegrationName string              `json:"integrationName"`
	Resources       []vantaControlEntry `json:"resources"`
}

type vantaControlEntry struct {
	UniqueID    string `json:"uniqueId"`
	DisplayName string `json:"displayName"`
	Status      string `json:"status"` // "PASSING", "FAILING", "WARNING"
	Description string `json:"description"`
}

func mapToVantaEvidence(record *types.EvidenceRecord) vantaEvidence {
	var controls []vantaControl
	for _, c := range record.Controls {
		controls = append(controls, vantaControl{
			Framework:   c.Framework,
			ControlID:   c.ControlID,
			ControlName: c.ControlName,
			Status:      c.Status,
			Violations:  c.Violations,
			Evidence:    c.Evidence,
		})
	}

	return vantaEvidence{
		DisplayName: fmt.Sprintf("Plexar Scan — %s/%s", record.ClusterName, record.Namespace),
		Description: fmt.Sprintf("Automated compliance evidence from Plexar scan at %s. Cluster score: %d/100, %d pods, %d controls evaluated.",
			record.Timestamp.Format(time.RFC3339), record.ClusterScore, record.TotalPods, len(record.Controls)),
		UniqueID: record.ID,
		Body: vantaEvidenceBody{
			ClusterName:     record.ClusterName,
			Namespace:       record.Namespace,
			ScanTimestamp:   record.Timestamp,
			ClusterScore:    record.ClusterScore,
			TotalPods:       record.TotalPods,
			NetworkPolicies: record.NetworkPolicies,
			Summary:         record.Summary,
			Controls:        controls,
			HashChain: vantaHashChain{
				RecordHash:   record.Hash,
				PreviousHash: record.PrevHash,
			},
		},
	}
}

func mapToVantaControls(controls []types.ControlEvidence, clusterName string) vantaControlsPayload {
	var entries []vantaControlEntry
	for _, c := range controls {
		status := "FAILING"
		switch c.Status {
		case "pass":
			status = "PASSING"
		case "partial", "warn":
			status = "WARNING"
		}

		entries = append(entries, vantaControlEntry{
			UniqueID:    fmt.Sprintf("plexar-%s-%s-%s", clusterName, c.Framework, c.ControlID),
			DisplayName: fmt.Sprintf("[%s] %s %s", c.Framework, c.ControlID, c.ControlName),
			Status:      status,
			Description: c.Evidence,
		})
	}

	return vantaControlsPayload{
		IntegrationName: "plexar",
		Resources:       entries,
	}
}
