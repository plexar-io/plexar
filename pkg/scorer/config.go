package scorer

import (
	"encoding/json"
	"fmt"
	"os"
)

// WeightConfig allows users to customize risk scoring weights
type WeightConfig struct {
	CVE         int `json:"cve"`
	Blast       int `json:"blast"`
	PolicyGap   int `json:"policyGap"`
	Permissions int `json:"permissions"`
	Sensitivity int `json:"sensitivity"`
}

// DefaultWeights returns the default scoring weights (must sum to 100)
func DefaultWeights() WeightConfig {
	return WeightConfig{
		CVE:         30,
		Blast:       25,
		PolicyGap:   20,
		Permissions: 15,
		Sensitivity: 10,
	}
}

// activeWeights holds the currently active scoring weights
var activeWeights = DefaultWeights()

// LoadWeights reads custom weights from a JSON config file.
// Falls back to defaults if the file doesn't exist.
func LoadWeights(path string) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read weights config: %w", err)
	}

	var cfg WeightConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse weights config: %w", err)
	}

	total := cfg.CVE + cfg.Blast + cfg.PolicyGap + cfg.Permissions + cfg.Sensitivity
	if total != 100 {
		return fmt.Errorf("weights must sum to 100, got %d (cve:%d + blast:%d + policyGap:%d + permissions:%d + sensitivity:%d)",
			total, cfg.CVE, cfg.Blast, cfg.PolicyGap, cfg.Permissions, cfg.Sensitivity)
	}

	activeWeights = cfg
	return nil
}

// ActiveWeights returns the currently active weights
func ActiveWeights() WeightConfig {
	return activeWeights
}
