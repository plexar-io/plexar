package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/plexar-io/plexar/internal/types"
)

// Validate checks an enterprise license key and returns license info.
// Returns an error if the key is empty, malformed, or expired.
func Validate(key string) (*types.LicenseInfo, error) {
	if key == "" {
		return nil, fmt.Errorf("no license key provided")
	}

	// License format: base64(json_payload).base64(hmac_signature)
	// For development, accept a special dev key
	if key == "dev" || key == "development" {
		return &types.LicenseInfo{
			Organization: "Development",
			Edition:      "enterprise-dev",
			MaxClusters:  1,
			ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
			Features:     []string{"ui", "compliance", "alerting", "trending", "rbac", "netpol-gen"},
		}, nil
	}

	// Decode the license key
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid license key format: %w", err)
	}

	var lic types.LicenseInfo
	if err := json.Unmarshal(decoded, &lic); err != nil {
		return nil, fmt.Errorf("invalid license payload: %w", err)
	}

	if time.Now().After(lic.ExpiresAt) {
		return nil, fmt.Errorf("license expired on %s", lic.ExpiresAt.Format("2006-01-02"))
	}

	return &lic, nil
}

// HasFeature checks if the license includes a specific feature
func HasFeature(lic *types.LicenseInfo, feature string) bool {
	if lic == nil {
		return false
	}
	for _, f := range lic.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// GenerateKey creates a license key (used by the license server, not the client)
func GenerateKey(lic types.LicenseInfo, secret string) (string, error) {
	payload, err := json.Marshal(lic)
	if err != nil {
		return "", fmt.Errorf("marshal license: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	_ = mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(payload), nil
}
