package alerting

import (
	"fmt"
	"time"

	"github.com/plexar-security/plexar/internal/types"
)

// Destination is where alerts get sent
type Destination interface {
	Send(event types.AlertEvent) error
	Name() string
}

// Engine evaluates alert rules against scan results
type Engine struct {
	rules        []types.AlertRule
	destinations []Destination
	lastResults  *types.ScanResult
	recentEvents []types.AlertEvent
}

// NewEngine creates an Engine with default rules
func NewEngine() *Engine {
	return &Engine{
		rules: defaultRules(),
	}
}

// AddDestination registers an alert destination
func (e *Engine) AddDestination(d Destination) {
	e.destinations = append(e.destinations, d)
}

// Rules returns the current alert rules
func (e *Engine) Rules() []types.AlertRule {
	return e.rules
}

// RecentEvents returns the last N alert events
func (e *Engine) RecentEvents(limit int) []types.AlertEvent {
	if limit > len(e.recentEvents) {
		limit = len(e.recentEvents)
	}
	return e.recentEvents[len(e.recentEvents)-limit:]
}

// Evaluate checks scan results against all enabled rules and fires alerts
func (e *Engine) Evaluate(result *types.ScanResult) {
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		var event *types.AlertEvent

		switch rule.ID {
		case "critical-cve-high-blast":
			for _, s := range result.Scores {
				if s.Vulns.Critical > 0 && s.Total >= 70 {
					event = &types.AlertEvent{
						RuleID:      rule.ID,
						RuleName:    rule.Name,
						Severity:    "critical",
						Message:     fmt.Sprintf("Critical CVE in %s (blast radius score: %d, %d critical CVEs)", s.PodName, s.Total, s.Vulns.Critical),
						PodName:     s.PodName,
						Remediation: fmt.Sprintf("Patch critical CVEs in image %s. Add NetworkPolicy if missing.", s.ImageName),
					}
					break
				}
			}

		case "cluster-score-increase":
			if e.lastResults != nil && result.ClusterScore-e.lastResults.ClusterScore > rule.Threshold {
				delta := result.ClusterScore - e.lastResults.ClusterScore
				event = &types.AlertEvent{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					Severity:    "high",
					Message:     fmt.Sprintf("Cluster risk score increased by %d (was %d, now %d)", delta, e.lastResults.ClusterScore, result.ClusterScore),
					ScoreDelta:  delta,
					Remediation: "Investigate new pods, CVEs, or NetworkPolicy changes that caused the score increase.",
				}
			}

		case "netpol-removed":
			if e.lastResults != nil && result.NetworkPolicies < e.lastResults.NetworkPolicies {
				event = &types.AlertEvent{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					Severity:    "high",
					Message:     fmt.Sprintf("NetworkPolicy removed — was %d, now %d", e.lastResults.NetworkPolicies, result.NetworkPolicies),
					Remediation: "Re-apply the removed NetworkPolicy or run: plexar generate netpol --namespace <ns>",
				}
			}

		case "compliance-drop":
			// Check if any compliance score dropped significantly
			if e.lastResults != nil {
				for i, comp := range result.Compliance {
					if i < len(e.lastResults.Compliance) {
						prev := e.lastResults.Compliance[i]
						if prev.Score-comp.Score > rule.Threshold {
							event = &types.AlertEvent{
								RuleID:      rule.ID,
								RuleName:    rule.Name,
								Severity:    "medium",
								Message:     fmt.Sprintf("%s compliance score dropped from %d%% to %d%%", comp.Framework, prev.Score, comp.Score),
								ScoreDelta:  comp.Score - prev.Score,
								Remediation: "Review failing controls in the compliance report and address findings.",
							}
							break
						}
					}
				}
			}

		case "new-internet-pod":
			for _, s := range result.Scores {
				if s.Blast.InternetAccess && !s.Blast.HasNetworkPolicy {
					// Only alert if this is new (simplified: always alert for now)
					if e.lastResults == nil {
						event = &types.AlertEvent{
							RuleID:   rule.ID,
							RuleName: rule.Name,
							Severity: "high",
							Message:  fmt.Sprintf("Pod %s has internet egress with no NetworkPolicy", s.PodName),
							PodName:  s.PodName,
						}
						break
					}
				}
			}
		}

		if event != nil {
			event.Timestamp = time.Now()
			e.recentEvents = append(e.recentEvents, *event)
			for _, dest := range e.destinations {
				if err := dest.Send(*event); err != nil {
					fmt.Printf("⚠  Alert delivery failed to %s: %v\n", dest.Name(), err)
				}
			}
		}
	}

	e.lastResults = result
}

func defaultRules() []types.AlertRule {
	return []types.AlertRule{
		{ID: "critical-cve-high-blast", Name: "Critical CVE in high blast radius pod", Description: "Fires when a critical CVE appears in a pod with score > 70", Enabled: true, Condition: "score > 70 AND critical_cves > 0"},
		{ID: "cluster-score-increase", Name: "Cluster risk score increase", Description: "Fires when cluster score increases by > 5 in one scan", Enabled: true, Condition: "delta > threshold", Threshold: 5},
		{ID: "netpol-removed", Name: "NetworkPolicy removed", Description: "Fires when a NetworkPolicy is deleted", Enabled: true, Condition: "netpol_count decreased"},
		{ID: "compliance-drop", Name: "Compliance score drop", Description: "Fires when any compliance framework drops by > 10%", Enabled: true, Condition: "delta > threshold", Threshold: 10},
		{ID: "new-internet-pod", Name: "New internet-exposed pod", Description: "Fires when a pod gains internet egress without NetworkPolicy", Enabled: false, Condition: "internet_access AND !has_netpol"},
		{ID: "weekly-digest", Name: "Weekly digest", Description: "Weekly summary sent every Monday 9am", Enabled: true, Condition: "schedule: 0 9 * * 1"},
	}
}
