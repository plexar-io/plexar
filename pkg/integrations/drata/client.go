package drata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/plexar-security/plexar/internal/types"
)

const (
	defaultBaseURL = "https://public-api.drata.com"
)

// Client interacts with the Drata API to push compliance evidence
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a Drata API client
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// SetBaseURL overrides the default Drata API URL (for testing)
func (c *Client) SetBaseURL(url string) {
	c.baseURL = url
}

// PushEvidence sends compliance evidence to Drata's external evidence API
func (c *Client) PushEvidence(record *types.EvidenceRecord) (*PushResult, error) {
	payload := mapToDrataEvidence(record)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}

	url := fmt.Sprintf("%s/public/external-evidence", c.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "plexar-security/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drata API request failed: %w", err)
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
		result.Error = fmt.Sprintf("drata returned %d: %v", resp.StatusCode, errBody)
		return result, fmt.Errorf("%s", result.Error)
	}

	var respBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err == nil {
		if id, ok := respBody["id"].(float64); ok {
			result.DrataID = fmt.Sprintf("%.0f", id)
		}
	}

	result.Success = true
	return result, nil
}

// PushControls sends control monitoring results to Drata
func (c *Client) PushControls(controls []types.ControlEvidence, clusterName string) (*PushResult, error) {
	payload := mapToDrataControls(controls, clusterName)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal controls: %w", err)
	}

	url := fmt.Sprintf("%s/public/controls/external", c.baseURL)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "plexar-security/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drata controls API request failed: %w", err)
	}
	defer resp.Body.Close()

	result := &PushResult{
		StatusCode: resp.StatusCode,
		Timestamp:  time.Now(),
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		result.Error = fmt.Sprintf("drata controls API returned %d", resp.StatusCode)
		return result, fmt.Errorf("%s", result.Error)
	}

	result.Success = true
	result.ControlsPushed = len(controls)
	return result, nil
}

// PushResult captures the outcome of a Drata evidence push
type PushResult struct {
	Success        bool      `json:"success"`
	StatusCode     int       `json:"statusCode"`
	Timestamp      time.Time `json:"timestamp"`
	RecordID       string    `json:"recordId,omitempty"`
	DrataID        string    `json:"drataId,omitempty"`
	ControlsPushed int       `json:"controlsPushed,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// ── Drata API payload types ──

type drataEvidence struct {
	ExternalEvidenceLibraryID int               `json:"externalEvidenceLibraryId,omitempty"`
	Name                      string            `json:"name"`
	Description               string            `json:"description"`
	CollectedAt               string            `json:"collectedAt"`
	Body                      drataEvidenceBody `json:"body"`
}

type drataEvidenceBody struct {
	Source          string                `json:"source"`
	ClusterName     string                `json:"clusterName"`
	Namespace       string                `json:"namespace"`
	ClusterScore    int                   `json:"clusterScore"`
	TotalPods       int                   `json:"totalPods"`
	NetworkPolicies int                   `json:"networkPolicies"`
	Summary         types.EvidenceSummary `json:"summary"`
	Controls        []drataControl        `json:"controls"`
	Integrity       drataIntegrity        `json:"integrity"`
}

type drataControl struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"controlId"`
	ControlName string `json:"controlName"`
	Status      string `json:"status"`
	Violations  int    `json:"violations"`
	Evidence    string `json:"evidence"`
}

type drataIntegrity struct {
	RecordHash   string `json:"recordHash"`
	PreviousHash string `json:"previousHash"`
	RecordID     string `json:"recordId"`
}

type drataControlsPayload struct {
	Controls []drataControlEntry `json:"controls"`
}

type drataControlEntry struct {
	ExternalID  string `json:"externalId"`
	Name        string `json:"name"`
	Status      string `json:"status"` // "PASSED", "FAILED", "WARNING", "NOT_APPLICABLE"
	Description string `json:"description"`
	TestedAt    string `json:"testedAt"`
}

func mapToDrataEvidence(record *types.EvidenceRecord) drataEvidence {
	var controls []drataControl
	for _, c := range record.Controls {
		controls = append(controls, drataControl{
			Framework:   c.Framework,
			ControlID:   c.ControlID,
			ControlName: c.ControlName,
			Status:      c.Status,
			Violations:  c.Violations,
			Evidence:    c.Evidence,
		})
	}

	return drataEvidence{
			Name: fmt.Sprintf("Plexar Compliance Scan — %s/%s", record.ClusterName, record.Namespace),
		Description: fmt.Sprintf("Automated Kubernetes compliance evidence. Cluster score: %d/100, %d pods scanned, %d controls evaluated. Hash-chained record %s.",
			record.ClusterScore, record.TotalPods, len(record.Controls), record.ID),
		CollectedAt: record.Timestamp.Format(time.RFC3339),
		Body: drataEvidenceBody{
			Source:          "plexar",
			ClusterName:     record.ClusterName,
			Namespace:       record.Namespace,
			ClusterScore:    record.ClusterScore,
			TotalPods:       record.TotalPods,
			NetworkPolicies: record.NetworkPolicies,
			Summary:         record.Summary,
			Controls:        controls,
			Integrity: drataIntegrity{
				RecordHash:   record.Hash,
				PreviousHash: record.PrevHash,
				RecordID:     record.ID,
			},
		},
	}
}

func mapToDrataControls(controls []types.ControlEvidence, clusterName string) drataControlsPayload {
	now := time.Now().Format(time.RFC3339)
	var entries []drataControlEntry
	for _, c := range controls {
		status := "FAILED"
		switch c.Status {
		case "pass":
			status = "PASSED"
		case "partial", "warn":
			status = "WARNING"
		}

		entries = append(entries, drataControlEntry{
			ExternalID:  fmt.Sprintf("plexar-%s-%s-%s", clusterName, c.Framework, c.ControlID),
			Name:        fmt.Sprintf("[%s] %s %s", c.Framework, c.ControlID, c.ControlName),
			Status:      status,
			Description: c.Evidence,
			TestedAt:    now,
		})
	}

	return drataControlsPayload{Controls: entries}
}
