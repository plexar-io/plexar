package evidence

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/plexar-security/plexar/internal/types"
)

// DetectDrift compares two consecutive evidence records and returns drift events.
// prev may be nil (first scan), in which case no drift is detected.
func DetectDrift(prev, curr *types.EvidenceRecord) []types.DriftEvent {
	if prev == nil || curr == nil {
		return nil
	}

	var events []types.DriftEvent
	now := time.Now()

	// Build control lookup from previous record
	prevControls := make(map[string]types.ControlEvidence)
	for _, c := range prev.Controls {
		key := c.Framework + "|" + c.ControlID
		prevControls[key] = c
	}

	// Compare each control in the current record against previous
	for _, c := range curr.Controls {
		key := c.Framework + "|" + c.ControlID
		pc, existed := prevControls[key]

		if !existed {
			continue // New control, not a drift
		}

		// Control regression: pass/warn → fail
		if (pc.Status == "pass" || pc.Status == "warn") && c.Status == "fail" {
			sev := "high"
			if c.Framework == "SOC 2" || c.Framework == "PCI DSS" {
				sev = "critical"
			}
			events = append(events, types.DriftEvent{
				ID:           driftID(now, key),
				Timestamp:    now,
				Category:     "control_regression",
				Severity:     sev,
				Framework:    c.Framework,
				ControlID:    c.ControlID,
				ControlName:  c.ControlName,
				PrevStatus:   pc.Status,
				NewStatus:    c.Status,
				PrevValue:    pc.Violations,
				NewValue:     c.Violations,
				Message:      fmt.Sprintf("%s %s (%s) regressed from %s to fail — %d violations", c.Framework, c.ControlID, c.ControlName, pc.Status, c.Violations),
				RecordID:     curr.ID,
				PrevRecordID: prev.ID,
			})
		}

		// Control recovery: fail → pass
		if pc.Status == "fail" && c.Status == "pass" {
			events = append(events, types.DriftEvent{
				ID:           driftID(now, key),
				Timestamp:    now,
				Category:     "control_recovery",
				Severity:     "info",
				Framework:    c.Framework,
				ControlID:    c.ControlID,
				ControlName:  c.ControlName,
				PrevStatus:   pc.Status,
				NewStatus:    c.Status,
				Message:      fmt.Sprintf("%s %s (%s) recovered — now passing", c.Framework, c.ControlID, c.ControlName),
				RecordID:     curr.ID,
				PrevRecordID: prev.ID,
			})
		}

		// Violation increase within a failing control
		if c.Status == "fail" && pc.Status == "fail" && c.Violations > pc.Violations {
			events = append(events, types.DriftEvent{
				ID:           driftID(now, key+"_viol"),
				Timestamp:    now,
				Category:     "violation_increase",
				Severity:     "medium",
				Framework:    c.Framework,
				ControlID:    c.ControlID,
				ControlName:  c.ControlName,
				PrevStatus:   pc.Status,
				NewStatus:    c.Status,
				PrevValue:    pc.Violations,
				NewValue:     c.Violations,
				Message:      fmt.Sprintf("%s %s violations increased from %d to %d", c.Framework, c.ControlID, pc.Violations, c.Violations),
				RecordID:     curr.ID,
				PrevRecordID: prev.ID,
			})
		}
	}

	// Cluster score regression
	if curr.ClusterScore > prev.ClusterScore+3 {
		events = append(events, types.DriftEvent{
			ID:           driftID(now, "cluster_score"),
			Timestamp:    now,
			Category:     "score_increase",
			Severity:     "high",
			PrevValue:    prev.ClusterScore,
			NewValue:     curr.ClusterScore,
			Message:      fmt.Sprintf("Cluster risk score increased from %d to %d", prev.ClusterScore, curr.ClusterScore),
			RecordID:     curr.ID,
			PrevRecordID: prev.ID,
		})
	}

	// NetworkPolicy removed
	if curr.NetworkPolicies < prev.NetworkPolicies {
		events = append(events, types.DriftEvent{
			ID:           driftID(now, "netpol_removed"),
			Timestamp:    now,
			Category:     "netpol_removed",
			Severity:     "critical",
			PrevValue:    prev.NetworkPolicies,
			NewValue:     curr.NetworkPolicies,
			Message:      fmt.Sprintf("NetworkPolicy count decreased from %d to %d", prev.NetworkPolicies, curr.NetworkPolicies),
			RecordID:     curr.ID,
			PrevRecordID: prev.ID,
		})
	}

	// Unprotected pods increased
	if curr.Summary.UnprotectedPods > prev.Summary.UnprotectedPods {
		events = append(events, types.DriftEvent{
			ID:           driftID(now, "pods_unprotected"),
			Timestamp:    now,
			Category:     "pods_unprotected",
			Severity:     "high",
			PrevValue:    prev.Summary.UnprotectedPods,
			NewValue:     curr.Summary.UnprotectedPods,
			Message:      fmt.Sprintf("Unprotected pods increased from %d to %d", prev.Summary.UnprotectedPods, curr.Summary.UnprotectedPods),
			RecordID:     curr.ID,
			PrevRecordID: prev.ID,
		})
	}

	// Critical CVE spike (>10% increase)
	if prev.Summary.CriticalCVEs > 0 && curr.Summary.CriticalCVEs > prev.Summary.CriticalCVEs {
		increase := curr.Summary.CriticalCVEs - prev.Summary.CriticalCVEs
		pct := (increase * 100) / prev.Summary.CriticalCVEs
		if pct >= 10 || increase >= 50 {
			events = append(events, types.DriftEvent{
				ID:           driftID(now, "cve_spike"),
				Timestamp:    now,
				Category:     "cve_spike",
				Severity:     "critical",
				PrevValue:    prev.Summary.CriticalCVEs,
				NewValue:     curr.Summary.CriticalCVEs,
				Message:      fmt.Sprintf("Critical CVEs increased by %d (%d%%) — from %d to %d", increase, pct, prev.Summary.CriticalCVEs, curr.Summary.CriticalCVEs),
				RecordID:     curr.ID,
				PrevRecordID: prev.ID,
			})
		}
	}

	// New pods detected
	if curr.TotalPods > prev.TotalPods {
		newCount := curr.TotalPods - prev.TotalPods
		sev := "info"
		if newCount >= 5 {
			sev = "medium"
		}
		events = append(events, types.DriftEvent{
			ID:           driftID(now, "new_pods"),
			Timestamp:    now,
			Category:     "new_pods",
			Severity:     sev,
			PrevValue:    prev.TotalPods,
			NewValue:     curr.TotalPods,
			Message:      fmt.Sprintf("%d new pod(s) detected — total went from %d to %d", newCount, prev.TotalPods, curr.TotalPods),
			RecordID:     curr.ID,
			PrevRecordID: prev.ID,
		})
	}

	// RBAC drift: new critical pods appeared
	if curr.Summary.CriticalPods > prev.Summary.CriticalPods {
		newCrit := curr.Summary.CriticalPods - prev.Summary.CriticalPods
		events = append(events, types.DriftEvent{
			ID:           driftID(now, "rbac_critical_increase"),
			Timestamp:    now,
			Category:     "rbac_drift",
			Severity:     "critical",
			PrevValue:    prev.Summary.CriticalPods,
			NewValue:     curr.Summary.CriticalPods,
			Message:      fmt.Sprintf("%d new critical-tier pod(s) — risk posture worsened from %d to %d critical pods", newCrit, prev.Summary.CriticalPods, curr.Summary.CriticalPods),
			RecordID:     curr.ID,
			PrevRecordID: prev.ID,
		})
	}

	// Internet-exposed pods increased
	if curr.Summary.InternetExposed > prev.Summary.InternetExposed {
		events = append(events, types.DriftEvent{
			ID:           driftID(now, "internet_exposed_increase"),
			Timestamp:    now,
			Category:     "exposure_drift",
			Severity:     "high",
			PrevValue:    prev.Summary.InternetExposed,
			NewValue:     curr.Summary.InternetExposed,
			Message:      fmt.Sprintf("Internet-exposed pods increased from %d to %d", prev.Summary.InternetExposed, curr.Summary.InternetExposed),
			RecordID:     curr.ID,
			PrevRecordID: prev.ID,
		})
	}

	return events
}

func driftID(t time.Time, key string) string {
	data := fmt.Sprintf("%d-%s", t.UnixNano(), key)
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("drift-%x", h[:6])
}
