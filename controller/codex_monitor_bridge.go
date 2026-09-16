package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay/channel/codex"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

const (
	codexMonitorBridgeCursorVersion       = 1
	codexMonitorBridgeEventOverlapSeconds = int64(30)
	codexMonitorBridgeEventSettleSeconds  = int64(2)
	codexMonitorBridgeDefaultEventLimit   = 500
	codexMonitorBridgeMaximumEventLimit   = 2000
	codexMonitorBridgeMaximumResponseSize = 1 << 20
)

type CodexMonitorBridgeCredentialRefreshFunc func(
	context.Context,
	int,
	service.CodexCredentialRefreshOptions,
) (*service.CodexOAuthKey, *model.Channel, error)

type codexMonitorBridgeCatalogItem struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	Status            int    `json:"status"`
	Enabled           bool   `json:"enabled"`
	Supported         bool   `json:"supported"`
	AccountRef        string `json:"account_ref,omitempty"`
	MaskedEmail       string `json:"masked_email,omitempty"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
}

type codexMonitorBridgeTokenMetadata struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
}

type codexMonitorBridgeCursor struct {
	Version        int    `json:"v"`
	Watermark      int64  `json:"watermark"`
	From           int64  `json:"from,omitempty"`
	Until          int64  `json:"until,omitempty"`
	AfterCreatedAt int64  `json:"after_created_at,omitempty"`
	AfterRequestID string `json:"after_request_id,omitempty"`
	AfterChannelID int    `json:"after_channel_id,omitempty"`
	Paging         bool   `json:"paging,omitempty"`
}

type codexMonitorBridgeEvent struct {
	EventID     string `json:"event_id"`
	ChannelID   int    `json:"channel_id"`
	CompletedAt int64  `json:"completed_at"`
}

type codexMonitorBridgeEventSource struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type codexMonitorBridgeSnapshot struct {
	SchemaVersion       int      `json:"schema_version"`
	CapturedAt          int64    `json:"captured_at"`
	ChannelID           int      `json:"channel_id"`
	AccountRef          string   `json:"account_ref"`
	Email               string   `json:"email,omitempty"`
	Usage               any      `json:"usage"`
	ResetCredits        any      `json:"reset_credits,omitempty"`
	UsageUpstreamStatus int      `json:"usage_upstream_status"`
	ResetUpstreamStatus int      `json:"reset_upstream_status,omitempty"`
	Partial             bool     `json:"partial"`
	PartialErrors       []string `json:"partial_errors"`
}

func GetCodexMonitorBridgeCatalog(c *gin.Context) {
	channels, err := model.ListCodexMonitorChannels()
	if err != nil {
		writeCodexMonitorBridgeError(c, http.StatusServiceUnavailable, "catalog_unavailable")
		return
	}

	items := make([]codexMonitorBridgeCatalogItem, 0, len(channels))
	for _, channel := range channels {
		if channel == nil {
			continue
		}
		item := codexMonitorBridgeCatalogItem{
			ID:      channel.Id,
			Name:    channel.Name,
			Status:  channel.Status,
			Enabled: channel.Status == common.ChannelStatusEnabled,
		}
		if channel.ChannelInfo.IsMultiKey {
			item.UnsupportedReason = "multi_key_channel"
			items = append(items, item)
			continue
		}
		oauthKey, parseErr := codex.ParseOAuthKey(strings.TrimSpace(channel.Key))
		if parseErr != nil {
			item.UnsupportedReason = "invalid_credential"
			items = append(items, item)
			continue
		}
		if strings.TrimSpace(oauthKey.AccountID) == "" {
			item.UnsupportedReason = "missing_account_id"
			items = append(items, item)
			continue
		}
		if strings.TrimSpace(oauthKey.AccessToken) == "" {
			item.UnsupportedReason = "missing_access_token"
			items = append(items, item)
			continue
		}
		item.Supported = true
		item.AccountRef = codexMonitorBridgeAccountRef(oauthKey.AccountID)
		item.MaskedEmail = maskCodexMonitorBridgeEmail(oauthKey.Email)
		items = append(items, item)
	}

	writeCodexMonitorBridgeJSON(c, http.StatusOK, gin.H{
		"schema_version": 1,
		"generated_at":   time.Now().Unix(),
		"token": codexMonitorBridgeTokenMetadata{
			ID:        c.GetString(middleware.CodexMonitorBridgeTokenIDContextKey),
			ExpiresAt: c.GetString(middleware.CodexMonitorBridgeTokenExpiresContextKey),
		},
		"channels": items,
	})
}

func GetCodexMonitorBridgeEvents(c *gin.Context) {
	limit := codexMonitorBridgeDefaultEventLimit
	if rawLimit := strings.TrimSpace(c.Query("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed < 1 || parsed > codexMonitorBridgeMaximumEventLimit {
			writeCodexMonitorBridgeError(c, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = parsed
	}

	now := time.Now().Unix()
	state := codexMonitorBridgeCursor{}
	rawCursor := strings.TrimSpace(c.Query("cursor"))
	if rawCursor != "" {
		decoded, err := decodeCodexMonitorBridgeCursor(rawCursor, now)
		if err != nil {
			writeCodexMonitorBridgeError(c, http.StatusBadRequest, "invalid_cursor")
			return
		}
		state = decoded
	}

	if !model.CodexMonitorEventSourceAvailable() {
		watermark := now - codexMonitorBridgeEventSettleSeconds
		if state.Watermark > watermark {
			watermark = state.Watermark
		}
		nextCursor, _ := encodeCodexMonitorBridgeCursor(codexMonitorBridgeCursor{
			Version:   codexMonitorBridgeCursorVersion,
			Watermark: watermark,
		})
		writeCodexMonitorBridgeJSON(c, http.StatusOK, gin.H{
			"schema_version": 1,
			"events":         []codexMonitorBridgeEvent{},
			"next_cursor":    nextCursor,
			"has_more":       false,
			"gap_detected":   false,
			"source": codexMonitorBridgeEventSource{
				Available: false,
				Reason:    "consume_logs_disabled",
			},
		})
		return
	}

	channels, err := model.ListCodexMonitorChannels()
	if err != nil {
		writeCodexMonitorBridgeError(c, http.StatusServiceUnavailable, "catalog_unavailable")
		return
	}
	channelIDs := make([]int, 0, len(channels))
	for _, channel := range channels {
		if channel != nil {
			channelIDs = append(channelIDs, channel.Id)
		}
	}

	from := state.From
	until := state.Until
	afterCreatedAt := state.AfterCreatedAt
	afterRequestID := state.AfterRequestID
	afterChannelID := state.AfterChannelID
	if !state.Paging {
		watermark := state.Watermark
		if watermark == 0 {
			watermark = now - codexMonitorBridgeEventOverlapSeconds
		}
		from = watermark - codexMonitorBridgeEventOverlapSeconds
		if from < 0 {
			from = 0
		}
		until = now - codexMonitorBridgeEventSettleSeconds
		if until < watermark {
			until = watermark
		}
		afterCreatedAt = 0
		afterRequestID = ""
		afterChannelID = 0
	}

	logs, hasMore, err := model.ListCodexMonitorEventLogs(
		channelIDs,
		from,
		until,
		afterCreatedAt,
		afterRequestID,
		afterChannelID,
		limit,
	)
	if err != nil {
		writeCodexMonitorBridgeError(c, http.StatusServiceUnavailable, "event_source_unavailable")
		return
	}

	events := make([]codexMonitorBridgeEvent, 0, len(logs))
	for _, entry := range logs {
		sum := sha256.Sum256([]byte(fmt.Sprintf("v1:%d:%d:%s", entry.ChannelID, entry.CreatedAt, entry.RequestID)))
		events = append(events, codexMonitorBridgeEvent{
			EventID:     "cme1_" + base64.RawURLEncoding.EncodeToString(sum[:]),
			ChannelID:   entry.ChannelID,
			CompletedAt: entry.CreatedAt,
		})
	}

	nextState := codexMonitorBridgeCursor{Version: codexMonitorBridgeCursorVersion, Watermark: until}
	if hasMore && len(logs) > 0 {
		last := logs[len(logs)-1]
		nextState = codexMonitorBridgeCursor{
			Version:        codexMonitorBridgeCursorVersion,
			Watermark:      state.Watermark,
			From:           from,
			Until:          until,
			AfterCreatedAt: last.CreatedAt,
			AfterRequestID: last.RequestID,
			AfterChannelID: last.ChannelID,
			Paging:         true,
		}
	}
	nextCursor, err := encodeCodexMonitorBridgeCursor(nextState)
	if err != nil {
		writeCodexMonitorBridgeError(c, http.StatusInternalServerError, "cursor_encoding_failed")
		return
	}

	oldest, hasOldest, err := model.OldestCodexMonitorEventTimestamp(channelIDs)
	if err != nil {
		writeCodexMonitorBridgeError(c, http.StatusServiceUnavailable, "event_source_unavailable")
		return
	}
	gapDetected := rawCursor != "" && hasOldest && state.Watermark > 0 && state.Watermark < oldest
	writeCodexMonitorBridgeJSON(c, http.StatusOK, gin.H{
		"schema_version": 1,
		"events":         events,
		"next_cursor":    nextCursor,
		"has_more":       hasMore,
		"gap_detected":   gapDetected,
		"source":         codexMonitorBridgeEventSource{Available: true},
	})
}

func NewCodexMonitorBridgeSnapshotHandler(refreshCredential CodexMonitorBridgeCredentialRefreshFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		getCodexMonitorBridgeSnapshot(c, refreshCredential)
	}
}

func getCodexMonitorBridgeSnapshot(c *gin.Context, refreshCredential CodexMonitorBridgeCredentialRefreshFunc) {
	channelID, err := strconv.Atoi(c.Param("id"))
	if err != nil || channelID <= 0 {
		writeCodexMonitorBridgeError(c, http.StatusBadRequest, "invalid_channel_id")
		return
	}
	channel, err := model.GetChannelById(channelID, true)
	if err != nil {
		writeCodexMonitorBridgeError(c, http.StatusServiceUnavailable, "channel_unavailable")
		return
	}
	if channel == nil {
		writeCodexMonitorBridgeError(c, http.StatusNotFound, "channel_not_found")
		return
	}
	if channel.Type != constant.ChannelTypeCodex || channel.ChannelInfo.IsMultiKey {
		writeCodexMonitorBridgeError(c, http.StatusUnprocessableEntity, "unsupported_channel")
		return
	}

	oauthKey, err := codex.ParseOAuthKey(strings.TrimSpace(channel.Key))
	if err != nil || strings.TrimSpace(oauthKey.AccountID) == "" || strings.TrimSpace(oauthKey.AccessToken) == "" {
		writeCodexMonitorBridgeError(c, http.StatusUnprocessableEntity, "unsupported_channel")
		return
	}
	accountRef := codexMonitorBridgeAccountRef(oauthKey.AccountID)
	client, err := service.GetHttpClientWithProxy(channel.GetSetting().Proxy)
	if err != nil {
		writeCodexMonitorBridgeError(c, http.StatusBadGateway, "upstream_client_unavailable")
		return
	}

	requestContext, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	usageStatus, usageBody, usageErr := service.FetchCodexWhamUsageLimited(
		requestContext,
		client,
		channel.GetBaseURL(),
		oauthKey.AccessToken,
		oauthKey.AccountID,
		codexMonitorBridgeMaximumResponseSize,
	)
	cancel()
	if usageErr != nil {
		writeCodexMonitorBridgeError(c, http.StatusBadGateway, "usage_fetch_failed")
		return
	}

	if (usageStatus == http.StatusUnauthorized || usageStatus == http.StatusForbidden) && strings.TrimSpace(oauthKey.RefreshToken) != "" {
		refreshContext, refreshCancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
		refreshedKey, refreshedChannel, refreshErr := refreshCredential(
			refreshContext,
			channelID,
			service.CodexCredentialRefreshOptions{ResetCaches: true},
		)
		refreshCancel()
		if refreshErr == nil && refreshedKey != nil && refreshedChannel != nil &&
			codexMonitorBridgeAccountRef(refreshedKey.AccountID) == accountRef {
			channel = refreshedChannel
			oauthKey.AccessToken = refreshedKey.AccessToken
			oauthKey.AccountID = refreshedKey.AccountID
			client, err = service.GetHttpClientWithProxy(channel.GetSetting().Proxy)
			if err == nil {
				retryContext, retryCancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
				usageStatus, usageBody, usageErr = service.FetchCodexWhamUsageLimited(
					retryContext,
					client,
					channel.GetBaseURL(),
					oauthKey.AccessToken,
					oauthKey.AccountID,
					codexMonitorBridgeMaximumResponseSize,
				)
				retryCancel()
			}
		}
	}
	if usageErr != nil || usageStatus < http.StatusOK || usageStatus >= http.StatusMultipleChoices {
		writeCodexMonitorBridgeError(c, http.StatusBadGateway, "usage_fetch_failed")
		return
	}

	var usagePayload any
	if err := common.Unmarshal(usageBody, &usagePayload); err != nil {
		writeCodexMonitorBridgeError(c, http.StatusBadGateway, "invalid_usage_response")
		return
	}
	email := ""
	if payload, ok := usagePayload.(map[string]any); ok {
		if candidate, ok := payload["email"].(string); ok && maskCodexMonitorBridgeEmail(candidate) != "" {
			email = strings.TrimSpace(candidate)
		}
	}
	sanitizeCodexMonitorBridgePayload(usagePayload)

	result := codexMonitorBridgeSnapshot{
		SchemaVersion:       1,
		CapturedAt:          time.Now().Unix(),
		ChannelID:           channelID,
		AccountRef:          accountRef,
		Email:               email,
		Usage:               usagePayload,
		UsageUpstreamStatus: usageStatus,
		PartialErrors:       []string{},
	}
	creditsContext, creditsCancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	creditsStatus, creditsBody, creditsErr := service.FetchCodexWhamRateLimitResetCreditsLimited(
		creditsContext,
		client,
		channel.GetBaseURL(),
		oauthKey.AccessToken,
		oauthKey.AccountID,
		codexMonitorBridgeMaximumResponseSize,
	)
	creditsCancel()
	result.ResetUpstreamStatus = creditsStatus
	if creditsErr != nil || creditsStatus < http.StatusOK || creditsStatus >= http.StatusMultipleChoices {
		result.Partial = true
		result.PartialErrors = append(result.PartialErrors, "reset_credits_unavailable")
	} else {
		var resetPayload any
		if err := common.Unmarshal(creditsBody, &resetPayload); err != nil {
			result.Partial = true
			result.PartialErrors = append(result.PartialErrors, "invalid_reset_credits_response")
		} else {
			sanitizeCodexMonitorBridgePayload(resetPayload)
			result.ResetCredits = resetPayload
		}
	}

	writeCodexMonitorBridgeJSON(c, http.StatusOK, result)
}

func codexMonitorBridgeAccountRef(accountID string) string {
	sum := sha256.Sum256([]byte("codex-account:v1:" + strings.TrimSpace(accountID)))
	return "cma1_" + hex.EncodeToString(sum[:])
}

func maskCodexMonitorBridgeEmail(email string) string {
	local, domain, found := strings.Cut(strings.TrimSpace(email), "@")
	if !found || local == "" || domain == "" {
		return ""
	}
	characters := []rune(local)
	return string(characters[0]) + "***@" + domain
}

func sanitizeCodexMonitorBridgePayload(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalizedKey := strings.ToLower(strings.TrimSpace(key))
			switch normalizedKey {
			case "email":
				if email, ok := child.(string); ok {
					typed[key] = maskCodexMonitorBridgeEmail(email)
				} else {
					typed[key] = "[redacted]"
				}
			case "account_id", "access_token", "refresh_token", "id_token", "authorization", "proxy", "base_url", "key", "secret", "password":
				typed[key] = "[redacted]"
			default:
				sanitizeCodexMonitorBridgePayload(child)
			}
		}
	case []any:
		for _, child := range typed {
			sanitizeCodexMonitorBridgePayload(child)
		}
	}
}

func encodeCodexMonitorBridgeCursor(cursor codexMonitorBridgeCursor) (string, error) {
	encoded, err := common.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return "cmc1." + base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeCodexMonitorBridgeCursor(raw string, now int64) (codexMonitorBridgeCursor, error) {
	prefix, payload, found := strings.Cut(raw, ".")
	if !found || prefix != "cmc1" || payload == "" {
		return codexMonitorBridgeCursor{}, errors.New("invalid cursor envelope")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || len(decoded) > 4096 {
		return codexMonitorBridgeCursor{}, errors.New("invalid cursor payload")
	}
	var cursor codexMonitorBridgeCursor
	if err := common.Unmarshal(decoded, &cursor); err != nil {
		return codexMonitorBridgeCursor{}, errors.New("invalid cursor JSON")
	}
	if cursor.Version != codexMonitorBridgeCursorVersion || cursor.Watermark < 0 || cursor.Watermark > now+60 {
		return codexMonitorBridgeCursor{}, errors.New("invalid cursor position")
	}
	if cursor.Paging {
		if cursor.From < 0 || cursor.Until < cursor.From || cursor.Until > now+60 ||
			cursor.AfterCreatedAt <= 0 || cursor.AfterCreatedAt < cursor.From || cursor.AfterCreatedAt > cursor.Until ||
			cursor.AfterRequestID == "" || cursor.AfterChannelID <= 0 {
			return codexMonitorBridgeCursor{}, errors.New("invalid paging cursor")
		}
	}
	return cursor, nil
}

func writeCodexMonitorBridgeJSON(c *gin.Context, status int, payload any) {
	encoded, err := common.Marshal(payload)
	if err != nil {
		writeCodexMonitorBridgeError(c, http.StatusInternalServerError, "response_encoding_failed")
		return
	}
	if len(encoded) > codexMonitorBridgeMaximumResponseSize {
		writeCodexMonitorBridgeError(c, http.StatusBadGateway, "response_too_large")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Data(status, "application/json; charset=utf-8", encoded)
}

func writeCodexMonitorBridgeError(c *gin.Context, status int, code string) {
	encoded, _ := common.Marshal(gin.H{"error": code})
	c.Header("Cache-Control", "no-store")
	c.Data(status, "application/json; charset=utf-8", encoded)
}
