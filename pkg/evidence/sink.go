package evidence

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/plexar-security/plexar/internal/types"
)

// Sink is the interface for pluggable evidence destinations
type Sink interface {
	// Name returns a human-readable name for this sink
	Name() string
	// Push sends an evidence record to the sink
	Push(record *types.EvidenceRecord) error
}

// SinkConfig describes a configured evidence sink
type SinkConfig struct {
	Type     string            `json:"type"`     // s3, webhook
	URL      string            `json:"url"`      // sink destination URL
	Headers  map[string]string `json:"headers"`  // optional auth headers (webhook)
	Bucket   string            `json:"bucket"`   // S3 bucket name
	Region   string            `json:"region"`   // S3 region
	Endpoint string            `json:"endpoint"` // S3 custom endpoint (MinIO)
}

// SinkManager coordinates pushing evidence to all configured sinks
type SinkManager struct {
	mu    sync.RWMutex
	sinks []Sink
	log   []SinkLogEntry
}

// SinkLogEntry records a push attempt
type SinkLogEntry struct {
	SinkName string `json:"sinkName"`
	RecordID string `json:"recordId"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

// NewSinkManager creates a new SinkManager
func NewSinkManager() *SinkManager {
	return &SinkManager{}
}

// Add registers a sink
func (m *SinkManager) Add(s Sink) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sinks = append(m.sinks, s)
}

// HasSinks returns true if any sinks are configured
func (m *SinkManager) HasSinks() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sinks) > 0
}

// PushAll sends an evidence record to all configured sinks
func (m *SinkManager) PushAll(record *types.EvidenceRecord) []error {
	m.mu.RLock()
	sinks := make([]Sink, len(m.sinks))
	copy(sinks, m.sinks)
	m.mu.RUnlock()

	var errs []error
	for _, s := range sinks {
		entry := SinkLogEntry{
			SinkName: s.Name(),
			RecordID: record.ID,
		}

		if err := s.Push(record); err != nil {
			entry.Error = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		} else {
			entry.Success = true
		}

		m.mu.Lock()
		m.log = append(m.log, entry)
		m.mu.Unlock()
	}

	return errs
}

// Log returns recent push log entries
func (m *SinkManager) Log(limit int) []SinkLogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > len(m.log) {
		return m.log
	}
	return m.log[len(m.log)-limit:]
}

// ParseSinkDSN parses a sink URL into a SinkConfig.
// Formats:
//
//	s3://accessKey:secretKey@endpoint/bucket
//	webhook://https://example.com/hook
//	webhook://https://example.com/hook?header=Authorization:Bearer+token
func ParseSinkDSN(dsn string) (*SinkConfig, error) {
	if strings.HasPrefix(dsn, "s3://") {
		return parseS3DSN(dsn)
	}
	if strings.HasPrefix(dsn, "webhook://") {
		return parseWebhookDSN(dsn)
	}
	return nil, fmt.Errorf("unsupported sink DSN %q (must start with s3:// or webhook://)", dsn)
}

func parseS3DSN(dsn string) (*SinkConfig, error) {
	// s3://accessKey:secretKey@endpoint/bucket
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid S3 DSN: %w", err)
	}

	accessKey := u.User.Username()
	secretKey, _ := u.User.Password()
	endpoint := u.Host
	bucket := strings.TrimPrefix(u.Path, "/")

	if bucket == "" {
		return nil, fmt.Errorf("S3 DSN missing bucket: %s", dsn)
	}

	return &SinkConfig{
		Type:     "s3",
		Endpoint: endpoint,
		Bucket:   bucket,
		Headers: map[string]string{
			"access-key": accessKey,
			"secret-key": secretKey,
		},
	}, nil
}

func parseWebhookDSN(dsn string) (*SinkConfig, error) {
	// webhook://https://example.com/hook?header=Authorization:Bearer+token
	raw := strings.TrimPrefix(dsn, "webhook://")

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook DSN: %w", err)
	}

	headers := make(map[string]string)
	for _, h := range u.Query()["header"] {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Remove header params from URL
	q := u.Query()
	q.Del("header")
	u.RawQuery = q.Encode()

	return &SinkConfig{
		Type:    "webhook",
		URL:     u.String(),
		Headers: headers,
	}, nil
}

// NewSinkFromConfig creates a Sink from a SinkConfig
func NewSinkFromConfig(cfg *SinkConfig) (Sink, error) {
	switch cfg.Type {
	case "s3":
		return NewS3Sink(cfg.Endpoint, cfg.Bucket, cfg.Headers["access-key"], cfg.Headers["secret-key"])
	case "webhook":
		return NewWebhookSink(cfg.URL, cfg.Headers)
	default:
		return nil, fmt.Errorf("unsupported sink type %q", cfg.Type)
	}
}
