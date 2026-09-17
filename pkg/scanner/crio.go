package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Image source constants
const (
	ImageSourceAuto       = "auto"
	ImageSourceCRIO       = "crio"
	ImageSourceContainerd = "containerd"
	ImageSourceDocker     = "docker"
)

// DetectImageSource probes the node for available container runtimes.
// Returns the detected runtime, or empty string to let Trivy try all defaults.
func DetectImageSource() string {
	if _, err := os.Stat("/run/crio/crio.sock"); err == nil {
		if _, err := exec.LookPath("skopeo"); err == nil {
			return ImageSourceCRIO
		}
	}
	if _, err := os.Stat("/run/containerd/containerd.sock"); err == nil {
		return ImageSourceContainerd
	}
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return ImageSourceDocker
	}
	return ""
}

// CRIOResolver maps pod image names to CRI-O containers-storage references
// and exports them as tarballs for Trivy scanning.
type CRIOResolver struct {
	mapping    map[string]string // normalized short name -> full CRI-O storage reference
	once       sync.Once
	initErr    error
	imageCount int // number of images indexed from CRI-O storage
}

// crictl images -o json output structure
type crictlImageList struct {
	Images []crictlImageEntry `json:"images"`
}

type crictlImageEntry struct {
	ID          string   `json:"id"`
	RepoTags    []string `json:"repoTags"`
	RepoDigests []string `json:"repoDigests"`
	Size        string   `json:"size"`
}

// Init builds the image mapping from crictl.
func (c *CRIOResolver) Init() error {
	c.once.Do(func() {
		c.mapping = make(map[string]string)

		cmd := exec.Command("/bin/sh", "-c", "crictl images -o json 2>/dev/null")
		output, err := cmd.Output()
		if err != nil {
			c.initErr = fmt.Errorf("crictl images failed: %w", err)
			return
		}

		var result crictlImageList
		if err := json.Unmarshal(output, &result); err != nil {
			c.initErr = fmt.Errorf("failed to parse crictl output: %w", err)
			return
		}

		for _, img := range result.Images {
			for _, tag := range img.RepoTags {
				// Store exact reference
				c.mapping[tag] = tag

				// Store with stripped registry prefix for matching against pod specs
				short := stripRegistryPrefix(tag)
				if short != tag {
					c.mapping[short] = tag
				}
			}
		}

		// Logged via scanner progress writer, not log.Printf, to avoid polluting the TUI
		c.imageCount = len(result.Images)
	})
	return c.initErr
}

// stripRegistryPrefix removes the registry hostname from an image reference.
// e.g. "registry.kube-system.svc.cluster.case.local:30012/infra/appmgr/appmgr:2.7.12"
// -> "infra/appmgr/appmgr:2.7.12"
func stripRegistryPrefix(ref string) string {
	slashIdx := strings.Index(ref, "/")
	if slashIdx < 0 {
		return ref
	}

	prefix := ref[:slashIdx]
	// If the prefix contains a dot or colon, it's a registry hostname
	if strings.Contains(prefix, ".") || strings.Contains(prefix, ":") {
		return ref[slashIdx+1:]
	}
	return ref
}

// Resolve finds the full CRI-O storage reference for a pod image name.
func (c *CRIOResolver) Resolve(imageName string) (string, error) {
	if err := c.Init(); err != nil {
		return "", err
	}

	// Try exact match
	if full, ok := c.mapping[imageName]; ok {
		return full, nil
	}

	// Try stripping registry prefix from the input
	short := stripRegistryPrefix(imageName)
	if full, ok := c.mapping[short]; ok {
		return full, nil
	}

	// Fuzzy match: compare the repository+tag ignoring registry differences
	// Pod spec may say "infra/appmgr/appmgr:2.7.12-..." while CRI-O has
	// "registry.example.com:30012/infra/appmgr/appmgr:2.7.12-..."
	for key, full := range c.mapping {
		keyShort := stripRegistryPrefix(key)
		if keyShort == imageName || keyShort == short {
			return full, nil
		}
	}

	// Last resort: match by image basename + tag
	parts := strings.SplitN(imageName, ":", 2)
	if len(parts) == 2 {
		wantBase := lastPathComponent(parts[0])
		wantTag := parts[1]
		for key, full := range c.mapping {
			keyParts := strings.SplitN(key, ":", 2)
			if len(keyParts) == 2 && keyParts[1] == wantTag {
				if lastPathComponent(keyParts[0]) == wantBase {
					return full, nil
				}
			}
		}
	}

	return "", fmt.Errorf("image %q not found in CRI-O storage (%d images indexed)", imageName, len(c.mapping))
}

// lastPathComponent returns the last segment of a path.
// e.g. "infra/appmgr/appmgr" -> "appmgr"
func lastPathComponent(s string) string {
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		return s[idx+1:]
	}
	return s
}

// Export copies an image from CRI-O containers-storage to a docker-archive tar.
// Returns the tar path and a cleanup function.
// Uses a per-image 5-minute timeout so large images don't hit the namespace deadline.
func (c *CRIOResolver) Export(ctx context.Context, imageName string) (tarPath string, cleanup func(), err error) {
	fullRef, err := c.Resolve(imageName)
	if err != nil {
		return "", nil, err
	}

	h := sha256.Sum256([]byte(fullRef))
	tarPath = fmt.Sprintf("/tmp/plexar-crio-%x.tar", h[:8])

	// Per-image timeout: 15 minutes for skopeo export.
	// Enterprise images (Java app servers, NDFC) can be 1-2GB and take 10+ min.
	exportCtx, exportCancel := context.WithTimeout(ctx, 15*time.Minute)
	defer exportCancel()

	cmd := exec.CommandContext(exportCtx, "/bin/sh", "-c",
		fmt.Sprintf("skopeo copy containers-storage:%s docker-archive:%s 2>&1", fullRef, tarPath))

	output, cmdErr := cmd.CombinedOutput()
	if cmdErr != nil {
		os.Remove(tarPath)
		errMsg := strings.TrimSpace(string(output))
		if exportCtx.Err() == context.DeadlineExceeded {
			return "", nil, fmt.Errorf("skopeo export timed out for %s (>15min, image may be too large)", fullRef)
		}
		return "", nil, fmt.Errorf("skopeo export failed for %s: %w (%s)", fullRef, cmdErr, errMsg)
	}

	cleanup = func() { os.Remove(tarPath) }
	return tarPath, cleanup, nil
}
