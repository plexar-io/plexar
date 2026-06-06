package integrations

import (
	"fmt"
	"time"

	"github.com/plexar-io/plexar/internal/types"
	"github.com/plexar-io/plexar/pkg/integrations/drata"
	"github.com/plexar-io/plexar/pkg/integrations/vanta"
)

// Provider represents a compliance platform integration
type Provider interface {
	Name() string
	PushEvidence(record *types.EvidenceRecord) error
	PushControls(controls []types.ControlEvidence, clusterName string) error
}

// Manager coordinates evidence pushes to all configured providers
type Manager struct {
	providers []Provider
	pushLog   []PushLogEntry
}

// PushLogEntry records an evidence push attempt
type PushLogEntry struct {
	Provider  string    `json:"provider"`
	Timestamp time.Time `json:"timestamp"`
	RecordID  string    `json:"recordId,omitempty"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Controls  int       `json:"controls,omitempty"`
}

// NewManager creates an integration manager
func NewManager() *Manager {
	return &Manager{}
}

// AddVanta registers a Vanta integration
func (m *Manager) AddVanta(apiToken string) {
	m.providers = append(m.providers, &vantaProvider{client: vanta.NewClient(apiToken)})
}

// AddDrata registers a Drata integration
func (m *Manager) AddDrata(apiKey string) {
	m.providers = append(m.providers, &drataProvider{client: drata.NewClient(apiKey)})
}

// HasProviders returns true if any integrations are configured
func (m *Manager) HasProviders() bool {
	return len(m.providers) > 0
}

// PushEvidence sends evidence to all configured providers
func (m *Manager) PushEvidence(record *types.EvidenceRecord) []error {
	var errs []error
	for _, p := range m.providers {
		entry := PushLogEntry{
			Provider:  p.Name(),
			Timestamp: time.Now(),
			RecordID:  record.ID,
		}

		if err := p.PushEvidence(record); err != nil {
			entry.Error = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
		} else {
			entry.Success = true
		}

		m.pushLog = append(m.pushLog, entry)
	}
	return errs
}

// PushControls sends control status to all configured providers
func (m *Manager) PushControls(controls []types.ControlEvidence, clusterName string) []error {
	var errs []error
	for _, p := range m.providers {
		entry := PushLogEntry{
			Provider:  p.Name(),
			Timestamp: time.Now(),
			Controls:  len(controls),
		}

		if err := p.PushControls(controls, clusterName); err != nil {
			entry.Error = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
		} else {
			entry.Success = true
		}

		m.pushLog = append(m.pushLog, entry)
	}
	return errs
}

// Log returns recent push log entries
func (m *Manager) Log(limit int) []PushLogEntry {
	if limit <= 0 || limit > len(m.pushLog) {
		return m.pushLog
	}
	return m.pushLog[len(m.pushLog)-limit:]
}

// ── Provider wrappers ──

type vantaProvider struct {
	client *vanta.Client
}

func (v *vantaProvider) Name() string { return "vanta" }

func (v *vantaProvider) PushEvidence(record *types.EvidenceRecord) error {
	_, err := v.client.PushEvidence(record)
	return err
}

func (v *vantaProvider) PushControls(controls []types.ControlEvidence, clusterName string) error {
	_, err := v.client.PushControls(controls, clusterName)
	return err
}

type drataProvider struct {
	client *drata.Client
}

func (d *drataProvider) Name() string { return "drata" }

func (d *drataProvider) PushEvidence(record *types.EvidenceRecord) error {
	_, err := d.client.PushEvidence(record)
	return err
}

func (d *drataProvider) PushControls(controls []types.ControlEvidence, clusterName string) error {
	_, err := d.client.PushControls(controls, clusterName)
	return err
}
