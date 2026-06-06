package evidence

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/plexar-io/plexar/internal/types"
)

// S3Sink pushes evidence records to an S3-compatible object store (AWS S3, MinIO, etc.)
type S3Sink struct {
	endpoint  string
	bucket    string
	accessKey string
	secretKey string
	client    *http.Client
}

// NewS3Sink creates a new S3-compatible evidence sink
func NewS3Sink(endpoint, bucket, accessKey, secretKey string) (*S3Sink, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("S3 endpoint is required")
	}
	if bucket == "" {
		return nil, fmt.Errorf("S3 bucket is required")
	}

	return &S3Sink{
		endpoint:  strings.TrimRight(endpoint, "/"),
		bucket:    bucket,
		accessKey: accessKey,
		secretKey: secretKey,
		client:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *S3Sink) Name() string {
	return fmt.Sprintf("s3://%s/%s", s.endpoint, s.bucket)
}

// Push uploads the evidence record as a JSON file to S3
// Path: YYYY/MM/DD/scan-{id}.json
func (s *S3Sink) Push(record *types.EvidenceRecord) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
	}

	t := record.Timestamp
	key := fmt.Sprintf("%s/%s/%s/scan-%s.json",
		t.Format("2006"), t.Format("01"), t.Format("02"), record.ID)

	return s.putObject(key, data)
}

// putObject uploads data to the S3-compatible endpoint using AWS Signature V4 (simplified)
func (s *S3Sink) putObject(key string, data []byte) error {
	urlStr := fmt.Sprintf("http://%s/%s/%s", s.endpoint, s.bucket, key)

	req, err := http.NewRequest(http.MethodPut, urlStr, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	now := time.Now().UTC()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-amz-date", now.Format("20060102T150405Z"))
	req.Header.Set("x-amz-content-sha256", sha256Hex(data))
	req.ContentLength = int64(len(data))

	// Sign the request (simplified AWS Sig V4)
	s.signRequest(req, data, now)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("S3 upload failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("S3 upload returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// signRequest adds AWS Signature V4 headers (simplified for S3-compatible stores)
func (s *S3Sink) signRequest(req *http.Request, payload []byte, now time.Time) {
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")
	region := "us-east-1"
	service := "s3"

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)

	// Canonical request
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.Host, sha256Hex(payload), amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalRequest := fmt.Sprintf("%s\n/%s/%s\n\n%s\n%s\n%s",
		req.Method,
		s.bucket,
		strings.TrimPrefix(req.URL.Path, "/"+s.bucket+"/"),
		canonicalHeaders,
		signedHeaders,
		sha256Hex(payload),
	)

	// String to sign
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate, credentialScope, sha256Hex([]byte(canonicalRequest)))

	// Signing key
	kDate := hmacSHA256([]byte("AWS4"+s.secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKey, credentialScope, signedHeaders, signature)

	req.Header.Set("Authorization", authHeader)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
