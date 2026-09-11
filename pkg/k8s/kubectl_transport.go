package k8s

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

// extractJSON finds and returns the JSON portion of kubectl output, stripping
// any non-JSON text (warnings, error prefixes) that wrappers like Cisco acs
// write to stdout instead of stderr.
func extractJSON(data []byte) []byte {
	// Fast path: already valid JSON
	if len(data) > 0 && (data[0] == '{' || data[0] == '[') {
		return data
	}
	// Find the first { or [ which starts the JSON body
	for i, b := range data {
		if b == '{' || b == '[' {
			return data[i:]
		}
	}
	return nil // no JSON found
}

// detectError checks for Kubernetes error messages in non-JSON output that
// some kubectl wrappers (e.g., Cisco acs) return with exit code 0.
// Returns (statusCode, message) if an error is detected, or (0, "") if not.
func detectError(data []byte) (int, string) {
	text := string(data)
	if strings.Contains(text, "Forbidden") {
		return 403, text
	}
	if strings.Contains(text, "NotFound") || strings.Contains(text, "not found") {
		return 404, text
	}
	if strings.Contains(text, "Unauthorized") {
		return 401, text
	}
	if strings.Contains(text, "Error from server") {
		return 500, text
	}
	return 0, ""
}

// makeStatusJSON creates a Kubernetes Status API response JSON.
func makeStatusJSON(code int, message string) []byte {
	reason := "InternalError"
	switch code {
	case 403:
		reason = "Forbidden"
	case 404:
		reason = "NotFound"
	case 401:
		reason = "Unauthorized"
	}
	return []byte(fmt.Sprintf(
		`{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":%q,"reason":%q,"code":%d}`,
		strings.TrimSpace(message), reason, code,
	))
}

// KubectlTransport implements http.RoundTripper by shelling out to kubectl.
// This is used in restricted environments (e.g., Cisco IKS) where direct TCP
// connections to the API server are blocked, but the kubectl binary has
// special network access through the platform.
type KubectlTransport struct{}

func (t *KubectlTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	path := req.URL.Path
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}

	log.Printf("[kubectl-transport] %s %s", req.Method, path)

	// Use /bin/sh to handle kubectl wrappers without shebangs (e.g., Cisco acs)
	cmd := exec.CommandContext(req.Context(), "/bin/sh", "-c", `kubectl get --raw "$0"`, path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitErr := cmd.Run()

	raw := stdout.Bytes()
	body := extractJSON(raw)

	// Case 1: valid JSON found — return it regardless of exit code
	if body != nil {
		log.Printf("[kubectl-transport] OK: %d bytes", len(body))
		return &http.Response{
			StatusCode:    200,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
			Header:        http.Header{"Content-Type": []string{"application/json"}},
			Request:       req,
		}, nil
	}

	// Case 2: no JSON — check for error messages in stdout (acs wrapper quirk)
	if code, msg := detectError(raw); code != 0 {
		log.Printf("[kubectl-transport] DETECTED %d: %s", code, strings.TrimSpace(msg))
		body := makeStatusJSON(code, msg)
		return &http.Response{
			StatusCode:    code,
			Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
			Header:        http.Header{"Content-Type": []string{"application/json"}},
			Request:       req,
		}, nil
	}

	// Case 3: command failed with no useful output
	errMsg := strings.TrimSpace(stderr.String())
	if errMsg == "" {
		errMsg = strings.TrimSpace(string(raw))
	}
	if exitErr != nil {
		errMsg = fmt.Sprintf("%s (exit: %v)", errMsg, exitErr)
	}
	log.Printf("[kubectl-transport] ERROR: %s", errMsg)

	body = makeStatusJSON(500, errMsg)
	return &http.Response{
		StatusCode:    500,
		Status:        "500 Internal Server Error",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Request:       req,
	}, nil
}
