package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/plexar-io/plexar/internal/types"
)

// Vault stores immutable, hash-chained compliance evidence records
type Vault struct {
	mu      sync.RWMutex
	dir     string
	records []types.EvidenceRecord
	drifts  []types.DriftEvent
}

// DefaultDir returns the default evidence storage directory
func DefaultDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".plexar", "evidence")
}

// NewVault creates a Vault at the given directory path and loads existing records
func NewVault(dir string) *Vault {
	v := &Vault{dir: dir}
	_ = v.loadFromDisk()
	return v
}

// Record persists a ScanResult as an immutable evidence record with hash chain
func (v *Vault) Record(result *types.ScanResult) (*types.EvidenceRecord, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Build control evidence from compliance results
	var controls []types.ControlEvidence
	for _, cr := range result.Compliance {
		for _, ctrl := range cr.Controls {
			controls = append(controls, types.ControlEvidence{
				Framework:   cr.Framework,
				ControlID:   ctrl.ID,
				ControlName: ctrl.Name,
				Status:      ctrl.Status,
				Violations:  ctrl.Violations,
				Evidence:    ctrl.Evidence,
			})
		}
	}

	// Build summary metrics
	summary := buildSummary(result)

	// Compute compliance score
	if len(result.Compliance) > 0 {
		total := 0
		for _, c := range result.Compliance {
			total += c.Score
		}
		summary.ComplianceScore = total / len(result.Compliance)
	}

	// Get previous hash for chain
	prevHash := ""
	if len(v.records) > 0 {
		prevHash = v.records[len(v.records)-1].Hash
	}

	rec := types.EvidenceRecord{
		ID:              generateID(),
		Timestamp:       time.Now(),
		ClusterName:     result.ClusterName,
		Namespace:       result.Namespace,
		ClusterScore:    result.ClusterScore,
		TotalPods:       result.TotalPods,
		NetworkPolicies: result.NetworkPolicies,
		Controls:        controls,
		Summary:         summary,
		PrevHash:        prevHash,
	}

	// Compute SHA-256 hash of the record (excluding the Hash field itself)
	rec.Hash = computeHash(rec)

	// Detect drift against the previous record
	var driftEvents []types.DriftEvent
	if len(v.records) > 0 {
		prev := &v.records[len(v.records)-1]
		driftEvents = DetectDrift(prev, &rec)
		v.drifts = append(v.drifts, driftEvents...)
	}

	v.records = append(v.records, rec)

	// Persist to disk
	if err := v.saveRecord(rec); err != nil {
		return nil, fmt.Errorf("persist evidence record: %w", err)
	}

	// Persist drift events
	for _, d := range driftEvents {
		_ = v.saveDrift(d)
	}

	return &rec, nil
}

// List returns all evidence records, optionally filtered by time range
func (v *Vault) List(from, to time.Time) []types.EvidenceRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if from.IsZero() && to.IsZero() {
		return v.records
	}

	var filtered []types.EvidenceRecord
	for _, r := range v.records {
		afterFrom := from.IsZero() || !r.Timestamp.Before(from)
		beforeTo := to.IsZero() || r.Timestamp.Before(to)
		if afterFrom && beforeTo {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// ListByControl returns evidence records for a specific framework+controlID
func (v *Vault) ListByControl(framework, controlID string, from, to time.Time) []ControlSnapshot {
	records := v.List(from, to)
	var snapshots []ControlSnapshot
	for _, r := range records {
		for _, c := range r.Controls {
			if c.Framework == framework && c.ControlID == controlID {
				snapshots = append(snapshots, ControlSnapshot{
					Timestamp:  r.Timestamp,
					RecordID:   r.ID,
					Status:     c.Status,
					Violations: c.Violations,
					Evidence:   c.Evidence,
					RecordHash: r.Hash,
				})
				break
			}
		}
	}
	return snapshots
}

// ControlSummary returns aggregate stats for each control across the evidence window
func (v *Vault) ControlSummary(from, to time.Time) []ControlStats {
	records := v.List(from, to)
	if len(records) == 0 {
		return nil
	}

	// Track per-control stats
	type tracker struct {
		framework   string
		controlID   string
		controlName string
		passCount   int
		failCount   int
		warnCount   int
		total       int
		lastStatus  string
		lastFailed  time.Time
	}

	statsMap := make(map[string]*tracker)
	for _, r := range records {
		for _, c := range r.Controls {
			key := c.Framework + "|" + c.ControlID
			t, ok := statsMap[key]
			if !ok {
				t = &tracker{framework: c.Framework, controlID: c.ControlID, controlName: c.ControlName}
				statsMap[key] = t
			}
			t.total++
			t.lastStatus = c.Status
			switch c.Status {
			case "pass":
				t.passCount++
			case "fail":
				t.failCount++
				t.lastFailed = r.Timestamp
			case "warn":
				t.warnCount++
			}
		}
	}

	var stats []ControlStats
	for _, t := range statsMap {
		passRate := 0
		if t.total > 0 {
			passRate = (t.passCount * 100) / t.total
		}
		stats = append(stats, ControlStats{
			Framework:     t.framework,
			ControlID:     t.controlID,
			ControlName:   t.controlName,
			PassRate:      passRate,
			TotalRecords:  t.total,
			PassCount:     t.passCount,
			FailCount:     t.failCount,
			WarnCount:     t.warnCount,
			CurrentStatus: t.lastStatus,
			LastFailedAt:  t.lastFailed,
		})
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Framework != stats[j].Framework {
			return stats[i].Framework < stats[j].Framework
		}
		return stats[i].ControlID < stats[j].ControlID
	})

	return stats
}

// DriftEvents returns drift events, optionally filtered by time range and severity
func (v *Vault) DriftEvents(from, to time.Time, severity string) []types.DriftEvent {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var filtered []types.DriftEvent
	for _, d := range v.drifts {
		afterFrom := from.IsZero() || !d.Timestamp.Before(from)
		beforeTo := to.IsZero() || d.Timestamp.Before(to)
		matchSev := severity == "" || d.Severity == severity
		if afterFrom && beforeTo && matchSev {
			filtered = append(filtered, d)
		}
	}
	return filtered
}

// DriftCount returns the total number of drift events
func (v *Vault) DriftCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.drifts)
}

// Count returns the total number of stored evidence records
func (v *Vault) Count() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.records)
}

// Verify checks the integrity of the hash chain. Returns the index of the
// first broken link, or -1 if the chain is intact.
func (v *Vault) Verify() int {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for i, r := range v.records {
		// Verify hash
		expected := computeHash(r)
		if r.Hash != expected {
			return i
		}
		// Verify chain link
		if i > 0 && r.PrevHash != v.records[i-1].Hash {
			return i
		}
	}
	return -1
}

// ── Internal ──

func buildSummary(result *types.ScanResult) types.EvidenceSummary {
	var s types.EvidenceSummary
	for _, score := range result.Scores {
		switch score.Tier {
		case "critical":
			s.CriticalPods++
		case "high":
			s.HighPods++
		}
		if !score.Blast.HasNetworkPolicy {
			s.UnprotectedPods++
		}
		if score.Blast.InternetAccess {
			s.InternetExposed++
		}
		s.CriticalCVEs += score.Vulns.Critical
		s.HighCVEs += score.Vulns.High
	}
	return s
}

func computeHash(r types.EvidenceRecord) string {
	// Zero the Hash field before computing
	r.Hash = ""
	data, _ := json.Marshal(r)
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func generateID() string {
	now := time.Now()
	h := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", now.UnixNano(), now.Nanosecond())))
	return fmt.Sprintf("ev-%x", h[:8])
}

func (v *Vault) saveRecord(rec types.EvidenceRecord) error {
	if err := os.MkdirAll(v.dir, 0755); err != nil {
		return fmt.Errorf("create evidence dir: %w", err)
	}

	filename := fmt.Sprintf("%s_%s.json", rec.Timestamp.Format("2006-01-02T15-04-05"), rec.ID)
	path := filepath.Join(v.dir, filename)

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal evidence record: %w", err)
	}

	return os.WriteFile(path, data, 0444) // Read-only — immutable
}

func (v *Vault) saveDrift(d types.DriftEvent) error {
	driftDir := filepath.Join(v.dir, "drift")
	if err := os.MkdirAll(driftDir, 0755); err != nil {
		return err
	}
	filename := fmt.Sprintf("%s_%s.json", d.Timestamp.Format("2006-01-02T15-04-05"), d.ID)
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(driftDir, filename), data, 0444)
}

func (v *Vault) loadFromDisk() error {
	// Load evidence records
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return nil // Directory doesn't exist yet
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(v.dir, entry.Name()))
		if err != nil {
			continue
		}
		var rec types.EvidenceRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		v.records = append(v.records, rec)
	}

	sort.Slice(v.records, func(i, j int) bool {
		return v.records[i].Timestamp.Before(v.records[j].Timestamp)
	})

	// Load drift events
	driftDir := filepath.Join(v.dir, "drift")
	driftEntries, err := os.ReadDir(driftDir)
	if err != nil {
		return nil
	}
	for _, entry := range driftEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(driftDir, entry.Name()))
		if err != nil {
			continue
		}
		var d types.DriftEvent
		if err := json.Unmarshal(data, &d); err != nil {
			continue
		}
		v.drifts = append(v.drifts, d)
	}

	sort.Slice(v.drifts, func(i, j int) bool {
		return v.drifts[i].Timestamp.Before(v.drifts[j].Timestamp)
	})

	return nil
}

// ── Query Types ──

// ControlSnapshot is a single observation of a control at a point in time
type ControlSnapshot struct {
	Timestamp  time.Time `json:"timestamp"`
	RecordID   string    `json:"recordId"`
	Status     string    `json:"status"`
	Violations int       `json:"violations"`
	Evidence   string    `json:"evidence"`
	RecordHash string    `json:"recordHash"`
}

// ControlStats aggregates control pass/fail history over a time window
type ControlStats struct {
	Framework     string    `json:"framework"`
	ControlID     string    `json:"controlId"`
	ControlName   string    `json:"controlName"`
	PassRate      int       `json:"passRate"`
	TotalRecords  int       `json:"totalRecords"`
	PassCount     int       `json:"passCount"`
	FailCount     int       `json:"failCount"`
	WarnCount     int       `json:"warnCount"`
	CurrentStatus string    `json:"currentStatus"`
	LastFailedAt  time.Time `json:"lastFailedAt,omitempty"`
}
