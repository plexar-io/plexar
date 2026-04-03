package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type contextKey string

const (
	UserContextKey      contextKey = "plexar.user"
	NamespaceContextKey contextKey = "plexar.namespaces"
)

// UserInfo contains authenticated user information extracted from the JWT
type UserInfo struct {
	Subject    string   `json:"sub"`
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	Groups     []string `json:"groups"`
	Namespaces []string `json:"namespaces"`
}

// NoopMiddleware returns a pass-through middleware (no auth)
func NoopMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next
	}
}

// jwksCache caches the JWKS keys from the issuer
type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	issuerURL string
	expiresAt time.Time
}

// NewOIDCMiddleware creates an OIDC-based auth middleware.
// Validates JWT Bearer tokens against the issuer's JWKS endpoint.
// Supports Okta, Azure AD, Google Workspace, and any standard OIDC provider.
// The audience parameter restricts accepted tokens (empty = skip audience check).
func NewOIDCMiddleware(issuerURL string, audiences ...string) (func(http.Handler) http.Handler, error) {
	if issuerURL == "" {
		return NoopMiddleware(), nil
	}

	cache := &jwksCache{
		issuerURL: strings.TrimSuffix(issuerURL, "/"),
		keys:      make(map[string]*rsa.PublicKey),
	}

	// Fetch JWKS on startup to validate the issuer is reachable
	if err := cache.refresh(); err != nil {
		return nil, fmt.Errorf("OIDC issuer unreachable at %s: %w", issuerURL, err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health probes, metrics, and dashboard static assets
			p := r.URL.Path
			if p == "/healthz" || p == "/readyz" || p == "/metrics" ||
				p == "/" || p == "/index.html" ||
				strings.HasPrefix(p, "/assets/") {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"missing or invalid Authorization header"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			// Decode JWT (header.payload.signature)
			parts := strings.Split(tokenStr, ".")
			if len(parts) != 3 {
				http.Error(w, `{"error":"malformed JWT"}`, http.StatusUnauthorized)
				return
			}

			// Decode header to get kid
			headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				http.Error(w, `{"error":"invalid JWT header"}`, http.StatusUnauthorized)
				return
			}
			var header struct {
				Alg string `json:"alg"`
				Kid string `json:"kid"`
			}
			if err := json.Unmarshal(headerBytes, &header); err != nil {
				http.Error(w, `{"error":"invalid JWT header"}`, http.StatusUnauthorized)
				return
			}

			// Verify RSA signature
			if err := cache.verifySignature(parts, header.Kid); err != nil {
				http.Error(w, `{"error":"invalid JWT signature"}`, http.StatusUnauthorized)
				return
			}

			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				http.Error(w, `{"error":"invalid JWT payload"}`, http.StatusUnauthorized)
				return
			}

			var claims struct {
				Sub        string   `json:"sub"`
				Email      string   `json:"email"`
				Name       string   `json:"name"`
				Groups     []string `json:"groups"`
				Namespaces []string `json:"namespaces"`
				Aud        jsonAud  `json:"aud"`
				Iss        string   `json:"iss"`
				Exp        int64    `json:"exp"`
				Nbf        int64    `json:"nbf"`
			}
			if err := json.Unmarshal(payloadBytes, &claims); err != nil {
				http.Error(w, `{"error":"invalid JWT claims"}`, http.StatusUnauthorized)
				return
			}

			// Verify issuer matches
			if claims.Iss != cache.issuerURL {
				http.Error(w, `{"error":"token issuer mismatch"}`, http.StatusUnauthorized)
				return
			}

			now := time.Now().Unix()

			// Verify expiration
			if now > claims.Exp {
				http.Error(w, `{"error":"token expired"}`, http.StatusUnauthorized)
				return
			}

			// Verify not-before
			if claims.Nbf > 0 && now < claims.Nbf {
				http.Error(w, `{"error":"token not yet valid"}`, http.StatusUnauthorized)
				return
			}

			// Verify audience if configured
			if len(audiences) > 0 {
				if !claims.Aud.matchesAny(audiences) {
					http.Error(w, `{"error":"token audience mismatch"}`, http.StatusUnauthorized)
					return
				}
			}

			user := &UserInfo{
				Subject:    claims.Sub,
				Email:      claims.Email,
				Name:       claims.Name,
				Groups:     claims.Groups,
				Namespaces: claims.Namespaces,
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			if len(user.Namespaces) > 0 {
				ctx = context.WithValue(ctx, NamespaceContextKey, user.Namespaces)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

// jsonAud handles JWT aud field which can be a string or array of strings
type jsonAud []string

func (a *jsonAud) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = jsonAud{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*a = jsonAud(multi)
	return nil
}

func (a jsonAud) matchesAny(allowed []string) bool {
	for _, aud := range a {
		for _, want := range allowed {
			if aud == want {
				return true
			}
		}
	}
	return false
}

// NamespaceScopedMiddleware restricts API responses to namespaces the user has access to.
func NamespaceScopedMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, ok := r.Context().Value(NamespaceContextKey).([]string)
			if !ok || len(allowed) == 0 {
				// No namespace restriction — allow all
				next.ServeHTTP(w, r)
				return
			}

			// Check if requested namespace is in the allowed list
			requestedNS := r.URL.Query().Get("namespace")
			if requestedNS == "" {
				next.ServeHTTP(w, r)
				return
			}

			for _, ns := range allowed {
				if ns == requestedNS || ns == "*" {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, fmt.Sprintf(`{"error":"access denied to namespace %q"}`, requestedNS), http.StatusForbidden)
		})
	}
}

// GetUser extracts the authenticated user from the request context
func GetUser(r *http.Request) *UserInfo {
	user, _ := r.Context().Value(UserContextKey).(*UserInfo)
	return user
}

// verifySignature checks the RSA-SHA256 signature against the JWKS key
func (c *jwksCache) verifySignature(parts []string, kid string) error {
	key := c.getKey(kid)
	if key == nil {
		// Key not found — try refreshing JWKS (key rotation)
		if err := c.refresh(); err != nil {
			return fmt.Errorf("JWKS refresh failed: %w", err)
		}
		key = c.getKey(kid)
		if key == nil {
			return fmt.Errorf("unknown signing key: %s", kid)
		}
	}

	signedContent := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	hash := sha256.Sum256([]byte(signedContent))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sigBytes)
}

func (c *jwksCache) getKey(kid string) *rsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if cache needs refresh
	if time.Now().After(c.expiresAt) {
		return nil // will trigger refresh
	}

	if kid != "" {
		return c.keys[kid]
	}
	// No kid — return first key (single-key issuers)
	for _, k := range c.keys {
		return k
	}
	return nil
}

func (c *jwksCache) refresh() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	jwksURL := c.issuerURL + "/.well-known/jwks.json"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		// Try OpenID Configuration discovery first
		discoveryURL := c.issuerURL + "/.well-known/openid-configuration"
		resp, err = client.Get(discoveryURL)
		if err != nil {
			return fmt.Errorf("fetch OIDC discovery: %w", err)
		}
		defer resp.Body.Close()

		var discovery struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
			return fmt.Errorf("parse OIDC discovery: %w", err)
		}
		resp, err = client.Get(discovery.JWKSURI)
		if err != nil {
			return fmt.Errorf("fetch JWKS: %w", err)
		}
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		c.keys[key.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}
	}

	c.expiresAt = time.Now().Add(1 * time.Hour)
	return nil
}
