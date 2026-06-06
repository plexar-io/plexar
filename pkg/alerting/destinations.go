package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/plexar-io/plexar/internal/types"
)

// SlackDestination sends alerts to a Slack webhook
type SlackDestination struct {
	webhookURL string
	client     *http.Client
}

// NewSlackDestination creates a Slack alert destination
func NewSlackDestination(webhookURL string) *SlackDestination {
	return &SlackDestination{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackDestination) Name() string { return "slack" }

func (s *SlackDestination) Send(event types.AlertEvent) error {
	icon := "🛡️"
	color := "#36a64f"
	switch event.Severity {
	case "critical":
		icon = "🚨"
		color = "#cc0000"
	case "high":
		icon = "⚠️"
		color = "#ff8800"
	case "medium":
		icon = "📋"
		color = "#ddaa00"
	}

	// Build context fields
	var fields []map[string]interface{}
	if event.PodName != "" {
		fields = append(fields, map[string]interface{}{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*Pod:* `%s`", event.PodName),
		})
	}
	fields = append(fields, map[string]interface{}{
		"type": "mrkdwn",
		"text": fmt.Sprintf("*Severity:* %s %s", icon, event.Severity),
	})
	if event.ScoreDelta != 0 {
		deltaStr := fmt.Sprintf("%+d", event.ScoreDelta)
		fields = append(fields, map[string]interface{}{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*Score Delta:* %s", deltaStr),
		})
	}
	fields = append(fields, map[string]interface{}{
		"type": "mrkdwn",
		"text": fmt.Sprintf("*Rule:* %s", event.RuleName),
	})

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]string{
				"type":  "plain_text",
				"text":  fmt.Sprintf("%s Plexar Alert: %s", icon, event.RuleName),
				"emoji": "true",
			},
		},
		{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": event.Message,
			},
		},
		{
			"type":   "section",
			"fields": fields,
		},
	}

	if event.Remediation != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Remediation:*\n%s", event.Remediation),
			},
		})
	}

	blocks = append(blocks, map[string]interface{}{
		"type": "context",
		"elements": []map[string]string{
			{
				"type": "mrkdwn",
				"text": fmt.Sprintf("Plexar • %s", event.Timestamp.Format("2006-01-02 15:04:05 MST")),
			},
		},
	})

	payload := map[string]interface{}{
		"text":   fmt.Sprintf("%s [Plexar %s] %s", icon, event.Severity, event.Message),
		"blocks": blocks,
		"attachments": []map[string]interface{}{
			{"color": color},
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack webhook failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

// PagerDutyDestination sends alerts to PagerDuty Events API v2
type PagerDutyDestination struct {
	routingKey string
	client     *http.Client
}

// NewPagerDutyDestination creates a PagerDuty alert destination
func NewPagerDutyDestination(routingKey string) *PagerDutyDestination {
	return &PagerDutyDestination{
		routingKey: routingKey,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *PagerDutyDestination) Name() string { return "pagerduty" }

func (p *PagerDutyDestination) Send(event types.AlertEvent) error {
	severity := "warning"
	if event.Severity == "critical" {
		severity = "critical"
	}

	payload := map[string]interface{}{
		"routing_key":  p.routingKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":  fmt.Sprintf("[Plexar] %s", event.Message),
			"severity": severity,
			"source":   "plexar",
			"group":    "kubernetes-security",
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := p.client.Post("https://events.pagerduty.com/v2/enqueue", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pagerduty failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pagerduty returned %d", resp.StatusCode)
	}
	return nil
}

// JiraDestination creates Jira tickets for alerts
type JiraDestination struct {
	baseURL  string
	project  string
	apiToken string
	email    string
	client   *http.Client
}

// NewJiraDestination creates a Jira alert destination
func NewJiraDestination(baseURL, project, email, apiToken string) *JiraDestination {
	return &JiraDestination{
		baseURL:  baseURL,
		project:  project,
		email:    email,
		apiToken: apiToken,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (j *JiraDestination) Name() string { return "jira" }

func (j *JiraDestination) Send(event types.AlertEvent) error {
	priority := "Medium"
	if event.Severity == "critical" {
		priority = "Highest"
	} else if event.Severity == "high" {
		priority = "High"
	}

	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":     map[string]string{"key": j.project},
			"summary":     fmt.Sprintf("[Plexar] %s", event.Message),
			"description": fmt.Sprintf("Alert: %s\nRule: %s\nSeverity: %s\nPod: %s\nTime: %s", event.Message, event.RuleName, event.Severity, event.PodName, event.Timestamp.Format(time.RFC3339)),
			"issuetype":   map[string]string{"name": "Bug"},
			"priority":    map[string]string{"name": priority},
		},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", j.baseURL+"/rest/api/2/issue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(j.email, j.apiToken)

	resp, err := j.client.Do(req)
	if err != nil {
		return fmt.Errorf("jira failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("jira returned %d", resp.StatusCode)
	}
	return nil
}
