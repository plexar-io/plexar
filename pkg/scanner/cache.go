package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/plexar-security/plexar/internal/types"
)

const cacheTTL = 24 * time.Hour

type cachedResult struct {
	Image     string          `json:"image"`
	ScannedAt time.Time       `json:"scannedAt"`
	CVEs      []types.CVEInfo `json:"cves"`
}

func cacheDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".plexar", "cache")
}

func cacheKey(image string) string {
	h := sha256.Sum256([]byte(image))
	return fmt.Sprintf("%x.json", h[:8])
}

func loadCached(image string) ([]types.CVEInfo, bool) {
	path := filepath.Join(cacheDir(), cacheKey(image))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var cached cachedResult
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, false
	}

	// Expire after TTL
	if time.Since(cached.ScannedAt) > cacheTTL {
		return nil, false
	}

	return cached.CVEs, true
}

func saveCache(image string, cves []types.CVEInfo) {
	dir := cacheDir()
	os.MkdirAll(dir, 0755)

	cached := cachedResult{
		Image:     image,
		ScannedAt: time.Now(),
		CVEs:      cves,
	}

	data, err := json.Marshal(cached)
	if err != nil {
		return
	}

	path := filepath.Join(dir, cacheKey(image))
	os.WriteFile(path, data, 0644)
}
