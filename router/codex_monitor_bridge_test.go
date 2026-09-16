package router

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestCodexMonitorBridgeContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	database, err := gorm.Open(sqlite.Open("file:codex-monitor-bridge?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, database.AutoMigrate(&model.Channel{}, &model.Log{}))
	previousDB, previousLogDB := model.DB, model.LOG_DB
	previousLogEnabled := common.LogConsumeEnabled
	model.DB, model.LOG_DB = database, database
	common.LogConsumeEnabled = true
	t.Cleanup(func() {
		model.DB, model.LOG_DB = previousDB, previousLogDB
		common.LogConsumeEnabled = previousLogEnabled
	})

	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "tokens.json")
	oldToken := bridgeTestToken(1, "old")
	newToken := bridgeTestToken(2, "new")
	writeBridgeTestManifest(t, manifestPath, time.Now().Add(24*time.Hour), oldToken)
	t.Setenv("CODEX_MONITOR_BRIDGE_TOKEN_HASH_FILE", manifestPath)

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "Bearer upstream-access-secret", request.Header.Get("Authorization"))
		assert.Equal(t, "account-secret", request.Header.Get("chatgpt-account-id"))
		switch request.URL.Path {
		case "/backend-api/wham/usage":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"email":"owner@example.com","rate_limit":{"primary_window":{"used_percent":42,"limit_window_seconds":18000}}}`))
		case "/backend-api/wham/rate-limit-reset-credits":
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"error":"temporary"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(upstream.Close)
	baseURL := upstream.URL
	validKey, err := common.Marshal(map[string]string{
		"access_token": "upstream-access-secret", "account_id": "account-secret", "email": "credential@example.com",
	})
	require.NoError(t, err)
	secondKey, err := common.Marshal(map[string]string{
		"access_token": "second-access-secret", "account_id": "account-secret", "email": "credential@example.com",
	})
	require.NoError(t, err)
	require.NoError(t, database.Create(&[]model.Channel{
		{Id: 11, Type: constant.ChannelTypeCodex, Key: string(validKey), Name: "primary", Status: common.ChannelStatusEnabled, BaseURL: &baseURL},
		{Id: 12, Type: constant.ChannelTypeCodex, Key: string(secondKey), Name: "secondary", Status: common.ChannelStatusManuallyDisabled},
		{Id: 13, Type: constant.ChannelTypeCodex, Key: "not-json", Name: "broken", Status: common.ChannelStatusEnabled},
		{Id: 14, Type: constant.ChannelTypeCodex, Key: string(validKey), Name: "multi", Status: common.ChannelStatusEnabled, ChannelInfo: model.ChannelInfo{IsMultiKey: true}},
	}).Error)

	engine := gin.New()
	api := engine.Group("/api")
	registerCodexMonitorBridgeRoutes(api)

	t.Run("auth catalog and sensitive fields", func(t *testing.T) {
		unauthorized := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/catalog", "Bearer "+bridgeTestToken(3, "unknown"))
		assert.Equal(t, http.StatusUnauthorized, unauthorized.Code)
		assert.NotContains(t, unauthorized.Body.String(), "unknown-secret")

		response := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/catalog", "Bearer "+oldToken)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		body := response.Body.String()
		assert.Contains(t, body, `"id":11`)
		assert.Contains(t, body, `"unsupported_reason":"invalid_credential"`)
		assert.Contains(t, body, `"unsupported_reason":"multi_key_channel"`)
		assert.Contains(t, body, "c***@example.com")
		assert.NotContains(t, body, "account-secret")
		assert.NotContains(t, body, "upstream-access-secret")
		assert.NotContains(t, body, upstream.URL)
		assert.Equal(t, response.Header().Get("Cache-Control"), "no-store")
	})

	t.Run("manifest reload keeps last valid and rotates without restart", func(t *testing.T) {
		require.NoError(t, os.WriteFile(manifestPath, []byte(`{"version":1,"tokens":`), 0o600))
		stillAccepted := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/catalog", "Bearer "+oldToken)
		assert.Equal(t, http.StatusOK, stillAccepted.Code)

		writeBridgeTestManifest(t, manifestPath, time.Now().Add(24*time.Hour), oldToken, newToken)
		newAccepted := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/catalog", "Bearer "+newToken)
		assert.Equal(t, http.StatusOK, newAccepted.Code)

		writeBridgeTestManifest(t, manifestPath, time.Now().Add(24*time.Hour), newToken)
		oldRejected := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/catalog", "Bearer "+oldToken)
		assert.Equal(t, http.StatusUnauthorized, oldRejected.Code)
	})

	t.Run("expired token is rejected uniformly", func(t *testing.T) {
		expiredPath := filepath.Join(directory, "expired.json")
		expiredToken := bridgeTestToken(4, "expired")
		writeBridgeTestManifest(t, expiredPath, time.Now().Add(-time.Minute), expiredToken)
		t.Setenv("CODEX_MONITOR_BRIDGE_TOKEN_HASH_FILE", expiredPath)
		expiredEngine := gin.New()
		registerCodexMonitorBridgeRoutes(expiredEngine.Group("/api"))
		response := bridgeTestRequest(expiredEngine, "/api/integration/codex-monitor/v1/catalog", "Bearer "+expiredToken)
		assert.Equal(t, http.StatusUnauthorized, response.Code)
		assert.JSONEq(t, `{"error":"unauthorized"}`, response.Body.String())
	})

	t.Run("events paginate with opaque cursor and report source state", func(t *testing.T) {
		now := time.Now().Unix()
		empty := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/events", "Bearer "+newToken)
		require.Equal(t, http.StatusOK, empty.Code, empty.Body.String())
		assert.Contains(t, empty.Body.String(), `"events":[]`)
		require.NoError(t, database.Create(&[]model.Log{
			{CreatedAt: now - 10, Type: model.LogTypeConsume, ChannelId: 11, RequestId: "request-a", Content: "relay"},
			{CreatedAt: now - 9, Type: model.LogTypeConsume, ChannelId: 12, RequestId: "request-b", Content: "relay"},
			{CreatedAt: now - 8, Type: model.LogTypeConsume, ChannelId: 11, RequestId: "request-test", Content: "模型测试"},
		}).Error)
		first := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/events?limit=1", "Bearer "+newToken)
		require.Equal(t, http.StatusOK, first.Code, first.Body.String())
		var firstPage struct {
			Events []map[string]any `json:"events"`
			Cursor string           `json:"next_cursor"`
			More   bool             `json:"has_more"`
		}
		require.NoError(t, common.Unmarshal(first.Body.Bytes(), &firstPage))
		require.Len(t, firstPage.Events, 1)
		assert.True(t, firstPage.More)
		assert.True(t, strings.HasPrefix(firstPage.Cursor, "cmc1."))

		second := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/events?limit=1&cursor="+firstPage.Cursor, "Bearer "+newToken)
		require.Equal(t, http.StatusOK, second.Code, second.Body.String())
		var secondPage struct {
			Events []map[string]any `json:"events"`
			Cursor string           `json:"next_cursor"`
			More   bool             `json:"has_more"`
		}
		require.NoError(t, common.Unmarshal(second.Body.Bytes(), &secondPage))
		require.Len(t, secondPage.Events, 1)
		assert.False(t, secondPage.More)
		assert.NotEqual(t, firstPage.Events[0]["event_id"], secondPage.Events[0]["event_id"])
		assert.NotContains(t, second.Body.String(), "request-a")
		assert.NotContains(t, second.Body.String(), "request-b")
		assert.NotContains(t, second.Body.String(), "request-test")

		overlapped := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/events?cursor="+secondPage.Cursor, "Bearer "+newToken)
		require.Equal(t, http.StatusOK, overlapped.Code, overlapped.Body.String())
		var overlapPage struct {
			Events []map[string]any `json:"events"`
		}
		require.NoError(t, common.Unmarshal(overlapped.Body.Bytes(), &overlapPage))
		require.Len(t, overlapPage.Events, 2, "the bridge deliberately redelivers the overlap window")

		cursorPayload, err := common.Marshal(map[string]any{"v": 1, "watermark": now - 100})
		require.NoError(t, err)
		gapCursor := "cmc1." + base64.RawURLEncoding.EncodeToString(cursorPayload)
		gap := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/events?cursor="+gapCursor, "Bearer "+newToken)
		assert.Contains(t, gap.Body.String(), `"gap_detected":true`)

		common.LogConsumeEnabled = false
		disabled := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/events", "Bearer "+newToken)
		common.LogConsumeEnabled = true
		assert.Contains(t, disabled.Body.String(), `"available":false`)
		assert.Contains(t, disabled.Body.String(), "consume_logs_disabled")
	})

	t.Run("snapshot returns usage when reset credits fail", func(t *testing.T) {
		response := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/channels/11/snapshot", "Bearer "+newToken)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var snapshot struct {
			Email string         `json:"email"`
			Usage map[string]any `json:"usage"`
		}
		require.NoError(t, common.Unmarshal(response.Body.Bytes(), &snapshot))
		assert.Equal(t, "owner@example.com", snapshot.Email)
		assert.Equal(t, "o***@example.com", snapshot.Usage["email"])
		assert.Contains(t, response.Body.String(), `"used_percent":42`)
		assert.Contains(t, response.Body.String(), `"partial":true`)
		assert.Contains(t, response.Body.String(), "reset_credits_unavailable")
		assert.NotContains(t, response.Body.String(), "upstream-access-secret")
		assert.LessOrEqual(t, response.Body.Len(), 1<<20)
	})

	t.Run("snapshot rejects oversized upstream payload", func(t *testing.T) {
		oversized := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"value":"` + strings.Repeat("x", (1<<20)+1) + `"}`))
		}))
		defer oversized.Close()
		oversizedURL := oversized.URL
		require.NoError(t, database.Create(&model.Channel{
			Id: 15, Type: constant.ChannelTypeCodex, Key: string(validKey), Name: "oversized",
			Status: common.ChannelStatusEnabled, BaseURL: &oversizedURL,
		}).Error)
		response := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/channels/15/snapshot", "Bearer "+newToken)
		assert.Equal(t, http.StatusBadGateway, response.Code)
		assert.JSONEq(t, `{"error":"usage_fetch_failed"}`, response.Body.String())
	})

	t.Run("snapshot retries after credential refresh and persists the replacement", func(t *testing.T) {
		refreshUpstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			assert.Equal(t, "account-secret", request.Header.Get("chatgpt-account-id"))
			switch request.URL.Path {
			case "/backend-api/wham/usage":
				if request.Header.Get("Authorization") != "Bearer refreshed-access-secret" {
					writer.WriteHeader(http.StatusUnauthorized)
					return
				}
				_, _ = writer.Write([]byte(`{"rate_limit":{"primary_window":{"used_percent":18,"limit_window_seconds":18000}}}`))
			case "/backend-api/wham/rate-limit-reset-credits":
				assert.Equal(t, "Bearer refreshed-access-secret", request.Header.Get("Authorization"))
				_, _ = writer.Write([]byte(`{"available_count":2,"credits":[]}`))
			default:
				http.NotFound(writer, request)
			}
		}))
		defer refreshUpstream.Close()
		refreshURL := refreshUpstream.URL
		staleKey, err := common.Marshal(map[string]string{
			"access_token": "stale-access-secret", "refresh_token": "refresh-secret",
			"account_id": "account-secret", "email": "owner@example.com",
		})
		require.NoError(t, err)
		require.NoError(t, database.Create(&model.Channel{
			Id: 16, Type: constant.ChannelTypeCodex, Key: string(staleKey), Name: "refreshable",
			Status: common.ChannelStatusEnabled, BaseURL: &refreshURL,
		}).Error)

		refreshCalls := 0
		refresher := func(
			_ context.Context,
			channelID int,
			_ service.CodexCredentialRefreshOptions,
		) (*service.CodexOAuthKey, *model.Channel, error) {
			refreshCalls++
			assert.Equal(t, 16, channelID)
			refreshed := &service.CodexOAuthKey{
				AccessToken: "refreshed-access-secret", RefreshToken: "rotated-refresh-secret",
				AccountID: "account-secret", Email: "owner@example.com",
			}
			encoded, marshalErr := common.Marshal(refreshed)
			if marshalErr != nil {
				return nil, nil, marshalErr
			}
			if updateErr := database.Model(&model.Channel{}).Where("id = ?", channelID).Update("key", string(encoded)).Error; updateErr != nil {
				return nil, nil, updateErr
			}
			refreshedChannel, loadErr := model.GetChannelById(channelID, true)
			return refreshed, refreshedChannel, loadErr
		}
		refreshEngine := gin.New()
		registerCodexMonitorBridgeRoutesWithRefresher(refreshEngine.Group("/api"), refresher)
		response := bridgeTestRequest(refreshEngine, "/api/integration/codex-monitor/v1/channels/16/snapshot", "Bearer "+newToken)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Equal(t, 1, refreshCalls)
		assert.Contains(t, response.Body.String(), `"used_percent":18`)
		assert.Contains(t, response.Body.String(), `"available_count":2`)
		assert.Contains(t, response.Body.String(), `"partial":false`)
		var persisted model.Channel
		require.NoError(t, database.First(&persisted, 16).Error)
		assert.Contains(t, persisted.Key, "refreshed-access-secret")
		assert.NotContains(t, persisted.Key, "stale-access-secret")
	})

	t.Run("invalid authentication attempts are rate limited", func(t *testing.T) {
		status := 0
		for attempt := 0; attempt < 35; attempt++ {
			status = bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/catalog", "Bearer "+bridgeTestToken(byte(attempt+20), "attacker")).Code
			if status == http.StatusTooManyRequests {
				break
			}
		}
		assert.Equal(t, http.StatusTooManyRequests, status)
	})
}

func TestCodexMonitorBridgeIsNotRegisteredWithoutManifest(t *testing.T) {
	t.Setenv("CODEX_MONITOR_BRIDGE_TOKEN_HASH_FILE", "")
	engine := gin.New()
	registerCodexMonitorBridgeRoutes(engine.Group("/api"))
	response := bridgeTestRequest(engine, "/api/integration/codex-monitor/v1/catalog", "")
	assert.Equal(t, http.StatusNotFound, response.Code)
}

func TestCodexMonitorBridgeLogQueryDatabaseMatrix(t *testing.T) {
	dialect := strings.TrimSpace(os.Getenv("CODEX_MONITOR_BRIDGE_MATRIX_DIALECT"))
	dsn := strings.TrimSpace(os.Getenv("CODEX_MONITOR_BRIDGE_MATRIX_DSN"))
	if dialect == "" || dsn == "" {
		t.Skip("set CODEX_MONITOR_BRIDGE_MATRIX_DIALECT and CODEX_MONITOR_BRIDGE_MATRIX_DSN")
	}
	var dialector gorm.Dialector
	var databaseType common.DatabaseType
	switch dialect {
	case "mysql":
		dialector = mysql.Open(dsn)
		databaseType = common.DatabaseTypeMySQL
	case "postgres":
		dialector = postgres.Open(dsn)
		databaseType = common.DatabaseTypePostgreSQL
	default:
		t.Fatalf("unsupported matrix dialect %q", dialect)
	}
	database, err := gorm.Open(dialector, &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := database.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, database.Migrator().DropTable(&model.Log{}))
	require.NoError(t, database.AutoMigrate(&model.Log{}))
	previousLogDB := model.LOG_DB
	previousType := common.LogDatabaseType()
	model.LOG_DB = database
	common.SetLogDatabaseType(databaseType)
	t.Cleanup(func() {
		model.LOG_DB = previousLogDB
		common.SetLogDatabaseType(previousType)
	})
	now := time.Now().Unix()
	require.NoError(t, database.Create(&model.Log{
		CreatedAt: now, Type: model.LogTypeConsume, ChannelId: 57, RequestId: "matrix-request", Content: "relay",
	}).Error)
	rows, more, err := model.ListCodexMonitorEventLogs([]int{57}, now-1, now+1, 0, "", 0, 10)
	require.NoError(t, err)
	assert.False(t, more)
	require.Len(t, rows, 1)
	assert.Equal(t, "matrix-request", rows[0].RequestID)
	oldest, found, err := model.OldestCodexMonitorEventTimestamp([]int{57})
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, now, oldest)
}

func bridgeTestToken(fill byte, id string) string {
	return "cm1." + id + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func writeBridgeTestManifest(t *testing.T, path string, expiresAt time.Time, tokens ...string) {
	t.Helper()
	entries := make([]map[string]string, 0, len(tokens))
	for _, token := range tokens {
		parts := strings.Split(token, ".")
		digest := sha256.Sum256([]byte(parts[2]))
		entries = append(entries, map[string]string{
			"id": parts[1], "sha256": hex.EncodeToString(digest[:]), "expires_at": expiresAt.UTC().Format(time.RFC3339),
		})
	}
	contents, err := common.Marshal(map[string]any{"version": 1, "tokens": entries})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, contents, 0o600))
}

func bridgeTestRequest(handler http.Handler, path, authorization string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.RemoteAddr = "127.0.0.1:4567"
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
