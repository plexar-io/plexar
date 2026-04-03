package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/plexar-security/plexar/internal/types"
)

// WebhookSink pushes evidence records as JSON POST to a configurable URL
type WebhookSink struct {
	url     string
	headers map[string]string
	client  *http.Client
}

// NewWebhookSink creates a new webhook evidence sink
func NewWebhookSink(url string, headers map[string]string) (*WebhookSink, error) {
	if url == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}

	if headers == nil {
		headers = make(map[string]string)
	}

	return &WebhookSink{
		url:     url,
		headers: headers,
		client:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (w *WebhookSink) Name() string {
	return fmt.Sprintf("webhook://%s", w.url)
}

// Push sends the evidence record as a JSON POST to the webhook URL
func (w *WebhookSink) Push(record *types.EvidenceRecord) error {
	payload := webhookPayload{
		Event:     "evidence.recorded",
		Timestamp: record.Timestamp,
		Record:    record,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "plexar-evidence-sink/1.0")

	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// webhookPayload is the JSON envelope sent to webhook destinations
type webhookPayload struct {
	Event     string                `json:"event"`
	Timestamp time.Time             `json:"timestamp"`
	Record    *types.EvidenceRecord `json:"record"`
}
