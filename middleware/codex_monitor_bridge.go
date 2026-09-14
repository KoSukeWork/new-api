package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/gin-gonic/gin"
)

const (
	CodexMonitorBridgeTokenIDContextKey       = "codex_monitor_bridge_token_id"
	CodexMonitorBridgeTokenExpiresContextKey  = "codex_monitor_bridge_token_expires_at"
	codexMonitorBridgeManifestMaxBytes        = 1 << 20
	codexMonitorBridgeMaximumTokenLifetime    = 90 * 24 * time.Hour
	codexMonitorBridgeFailedAuthLimit         = 30
	codexMonitorBridgeFailedAuthWindowSeconds = int64(5 * 60)
)

type codexMonitorBridgeManifest struct {
	Version int                               `json:"version"`
	Tokens  []codexMonitorBridgeManifestToken `json:"tokens"`
}

type codexMonitorBridgeManifestToken struct {
	ID        string `json:"id"`
	SHA256    string `json:"sha256"`
	ExpiresAt string `json:"expires_at"`
}

type codexMonitorBridgeToken struct {
	hash      [sha256.Size]byte
	expiresAt time.Time
}

// CodexMonitorBridgeTokenVerifier hot-reloads a file containing token hashes.
// A malformed replacement never displaces the last valid manifest.
type CodexMonitorBridgeTokenVerifier struct {
	path string

	mu              sync.RWMutex
	tokens          map[string]codexMonitorBridgeToken
	loadedDigest    [sha256.Size]byte
	hasLoadedDigest bool
	failedDigest    [sha256.Size]byte
	hasFailedDigest bool
	failureLimiter  common.InMemoryRateLimiter
}

func NewCodexMonitorBridgeTokenVerifier(path string) *CodexMonitorBridgeTokenVerifier {
	verifier := &CodexMonitorBridgeTokenVerifier{path: strings.TrimSpace(path)}
	verifier.failureLimiter.Init(common.RateLimitKeyExpirationDuration)
	return verifier
}

func (v *CodexMonitorBridgeTokenVerifier) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenID, expiresAt, ok := v.verify(c.GetHeader("Authorization"), time.Now())
		if !ok {
			key := "codex-monitor-bridge:" + c.ClientIP()
			if !v.failureLimiter.Request(key, codexMonitorBridgeFailedAuthLimit, codexMonitorBridgeFailedAuthWindowSeconds) {
				c.Header("Retry-After", fmt.Sprintf("%d", codexMonitorBridgeFailedAuthWindowSeconds))
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
				c.Abort()
				return
			}
			logger.LogWarn(c.Request.Context(), "codex monitor bridge authentication failed: token_id="+safeCodexMonitorTokenID(tokenID))
			c.Header("WWW-Authenticate", `Bearer realm="codex-monitor-bridge"`)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		c.Set(CodexMonitorBridgeTokenIDContextKey, tokenID)
		c.Set(CodexMonitorBridgeTokenExpiresContextKey, expiresAt.UTC().Format(time.RFC3339))
		c.Next()
	}
}

func (v *CodexMonitorBridgeTokenVerifier) verify(authorization string, now time.Time) (string, time.Time, bool) {
	if v == nil || v.path == "" {
		return "", time.Time{}, false
	}
	v.reload(now)

	tokenID, secret, ok := parseCodexMonitorBridgeAuthorization(authorization)
	if !ok {
		return tokenID, time.Time{}, false
	}
	v.mu.RLock()
	token, exists := v.tokens[tokenID]
	v.mu.RUnlock()
	if !exists || !now.Before(token.expiresAt) {
		return tokenID, time.Time{}, false
	}

	secretBytes, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(secretBytes) != 32 {
		return tokenID, time.Time{}, false
	}
	digest := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(digest[:], token.hash[:]) != 1 {
		return tokenID, time.Time{}, false
	}
	return tokenID, token.expiresAt, true
}

func (v *CodexMonitorBridgeTokenVerifier) reload(now time.Time) {
	file, err := os.Open(v.path)
	if err != nil {
		v.recordReloadFailure(errors.New("cannot open token hash file"))
		return
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, codexMonitorBridgeManifestMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		v.recordReloadFailure(errors.New("cannot read token hash file"))
		return
	}
	if len(contents) > codexMonitorBridgeManifestMaxBytes {
		v.recordReloadFailure(errors.New("token hash file exceeds 1 MiB"))
		return
	}

	digest := sha256.Sum256(contents)
	v.mu.RLock()
	unchanged := v.hasLoadedDigest && digest == v.loadedDigest
	failedUnchanged := v.hasFailedDigest && digest == v.failedDigest
	v.mu.RUnlock()
	if unchanged || failedUnchanged {
		return
	}

	tokens, err := parseCodexMonitorBridgeManifest(contents, now)
	if err != nil {
		v.mu.Lock()
		v.failedDigest = digest
		v.hasFailedDigest = true
		v.mu.Unlock()
		v.recordReloadFailure(err)
		return
	}

	v.mu.Lock()
	v.tokens = tokens
	v.loadedDigest = digest
	v.hasLoadedDigest = true
	v.hasFailedDigest = false
	v.mu.Unlock()
}

func (v *CodexMonitorBridgeTokenVerifier) recordReloadFailure(err error) {
	message := "codex monitor bridge token manifest reload failed"
	if err != nil {
		message += ": " + err.Error()
	}
	common.SysError(message)
}

func parseCodexMonitorBridgeManifest(contents []byte, now time.Time) (map[string]codexMonitorBridgeToken, error) {
	var manifest codexMonitorBridgeManifest
	if err := common.Unmarshal(contents, &manifest); err != nil {
		return nil, errors.New("invalid JSON")
	}
	if manifest.Version != 1 {
		return nil, errors.New("unsupported manifest version")
	}
	if len(manifest.Tokens) == 0 || len(manifest.Tokens) > 100 {
		return nil, errors.New("manifest must contain 1 to 100 tokens")
	}

	tokens := make(map[string]codexMonitorBridgeToken, len(manifest.Tokens))
	for _, entry := range manifest.Tokens {
		if !validCodexMonitorTokenID(entry.ID) {
			return nil, errors.New("invalid token ID")
		}
		if _, exists := tokens[entry.ID]; exists {
			return nil, errors.New("duplicate token ID")
		}
		hashBytes, err := hex.DecodeString(strings.TrimSpace(entry.SHA256))
		if err != nil || len(hashBytes) != sha256.Size {
			return nil, errors.New("invalid token SHA-256")
		}
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(entry.ExpiresAt))
		if err != nil {
			return nil, errors.New("invalid token expiry")
		}
		if expiresAt.After(now.Add(codexMonitorBridgeMaximumTokenLifetime)) {
			return nil, errors.New("token expiry exceeds 90 days")
		}
		var digest [sha256.Size]byte
		copy(digest[:], hashBytes)
		tokens[entry.ID] = codexMonitorBridgeToken{hash: digest, expiresAt: expiresAt}
	}
	return tokens, nil
}

func parseCodexMonitorBridgeAuthorization(value string) (string, string, bool) {
	if !strings.HasPrefix(value, "Bearer ") || strings.Count(value, " ") != 1 {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(value, "Bearer "), ".")
	if len(parts) != 3 || parts[0] != "cm1" || !validCodexMonitorTokenID(parts[1]) || parts[2] == "" {
		if len(parts) >= 2 && validCodexMonitorTokenID(parts[1]) {
			return parts[1], "", false
		}
		return "", "", false
	}
	return parts[1], parts[2], true
}

func validCodexMonitorTokenID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safeCodexMonitorTokenID(value string) string {
	if validCodexMonitorTokenID(value) {
		return value
	}
	return "unknown"
}
