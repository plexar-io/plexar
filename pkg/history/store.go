package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/plexar-security/plexar/internal/types"
)

// Store persists scan snapshots for historical trending
type Store struct {
	mu        sync.RWMutex
	path      string
	snapshots []types.HistorySnapshot
	retention time.Duration // how long to keep snapshots
}

// DefaultPath returns the default history storage path
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".plexar", "history.json")
}

// NewStore creates a Store at the given file path with 90-day default retention
func NewStore(path string) *Store {
	s := &Store{path: path, retention: 90 * 24 * time.Hour}
	_ = s.loadFromDisk()
	return s
}

// SetRetention configures how long snapshots are kept
func (s *Store) SetRetention(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retention = d
}

// Latest returns the most recent snapshot, or nil if empty
func (s *Store) Latest() *types.HistorySnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.snapshots) == 0 {
		return nil
	}
	snap := s.snapshots[len(s.snapshots)-1]
	return &snap
}

// Delta returns the difference between the two most recent snapshots
func (s *Store) Delta() *SnapshotDelta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.snapshots) < 2 {
		return nil
	}
	prev := s.snapshots[len(s.snapshots)-2]
	curr := s.snapshots[len(s.snapshots)-1]
	return &SnapshotDelta{
		Timestamp:        curr.Timestamp,
		ScoreDelta:       curr.ClusterScore - prev.ClusterScore,
		PodsDelta:        curr.TotalPods - prev.TotalPods,
		CriticalDelta:    curr.CriticalPods - prev.CriticalPods,
		HighDelta:        curr.HighPods - prev.HighPods,
		UnprotectedDelta: curr.UnprotectedPods - prev.UnprotectedPods,
		CVEDelta:         curr.CriticalCVEs - prev.CriticalCVEs,
		ComplianceDelta:  curr.ComplianceScore - prev.ComplianceScore,
	}
}

// SnapshotDelta captures the change between two consecutive snapshots
type SnapshotDelta struct {
	Timestamp        time.Time `json:"timestamp"`
	ScoreDelta       int       `json:"scoreDelta"`
	PodsDelta        int       `json:"podsDelta"`
	CriticalDelta    int       `json:"criticalDelta"`
	HighDelta        int       `json:"highDelta"`
	UnprotectedDelta int       `json:"unprotectedDelta"`
	CVEDelta         int       `json:"cveDelta"`
	ComplianceDelta  int       `json:"complianceDelta"`
}

// Save persists a scan result as a history snapshot
func (s *Store) Save(result *types.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	criticalPods := 0
	highPods := 0
	unprotectedPods := 0
	criticalCVEs := 0

	for _, score := range result.Scores {
		switch score.Tier {
		case "critical":
			criticalPods++
		case "high":
			highPods++
		}
		if !score.Blast.HasNetworkPolicy {
			unprotectedPods++
		}
		criticalCVEs += score.Vulns.Critical
	}

	complianceScore := 0
	if len(result.Compliance) > 0 {
		total := 0
		for _, c := range result.Compliance {
			total += c.Score
		}
		complianceScore = total / len(result.Compliance)
	}

	snapshot := types.HistorySnapshot{
		Timestamp:       time.Now(),
		ClusterScore:    result.ClusterScore,
		TotalPods:       result.TotalPods,
		CriticalPods:    criticalPods,
		HighPods:        highPods,
		UnprotectedPods: unprotectedPods,
		CriticalCVEs:    criticalCVEs,
		ComplianceScore: complianceScore,
	}

	s.snapshots = append(s.snapshots, snapshot)

	// Purge snapshots older than retention period
	s.purge()

	return s.saveToDisk()
}

// Load returns all stored snapshots
func (s *Store) Load() ([]types.HistorySnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshots, nil
}

// LoadRange returns snapshots within a time range
func (s *Store) LoadRange(from, to time.Time) ([]types.HistorySnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []types.HistorySnapshot
	for _, snap := range s.snapshots {
		if (snap.Timestamp.After(from) || snap.Timestamp.Equal(from)) && snap.Timestamp.Before(to) {
			filtered = append(filtered, snap)
		}
	}
	return filtered, nil
}

// SeedDemo generates synthetic history data for demos
func (s *Store) SeedDemo(result *types.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.snapshots) > 0 {
		return nil // Already has data
	}

	now := time.Now()
	for i := 30; i > 0; i-- {
		t := now.Add(-time.Duration(i) * 24 * time.Hour)
		drift := i / 3
		s.snapshots = append(s.snapshots, types.HistorySnapshot{
			Timestamp:       t,
			ClusterScore:    result.ClusterScore - drift + (i % 5),
			TotalPods:       result.TotalPods,
			CriticalPods:    max(0, 4-(i/10)),
			HighPods:        max(0, 4-(i/15)),
			UnprotectedPods: result.TotalPods - (30 - i),
			CriticalCVEs:    max(0, 7-(i/5)),
			ComplianceScore: min(100, 40+(30-i)*2),
		})
	}

	sort.Slice(s.snapshots, func(i, j int) bool {
		return s.snapshots[i].Timestamp.Before(s.snapshots[j].Timestamp)
	})

	return s.saveToDisk()
}

func (s *Store) purge() {
	cutoff := time.Now().Add(-s.retention)
	idx := 0
	for idx < len(s.snapshots) && s.snapshots[idx].Timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		s.snapshots = s.snapshots[idx:]
	}
	// Hard cap at 5000 to prevent unbounded growth
	if len(s.snapshots) > 5000 {
		s.snapshots = s.snapshots[len(s.snapshots)-5000:]
	}
}

func (s *Store) loadFromDisk() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil // File doesn't exist yet
	}
	return json.Unmarshal(data, &s.snapshots)
}

func (s *Store) saveToDisk() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create history dir: %w", err)
	}
	data, err := json.MarshalIndent(s.snapshots, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal history: %w", err)
	}
	return os.WriteFile(s.path, data, 0644)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
