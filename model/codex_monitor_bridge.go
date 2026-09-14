package model

import (
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"gorm.io/gorm"
)

const codexMonitorChannelTestLogContent = "模型测试"

type CodexMonitorEventLog struct {
	ChannelID int    `gorm:"column:channel_id"`
	CreatedAt int64  `gorm:"column:created_at"`
	RequestID string `gorm:"column:request_id"`
}

func ListCodexMonitorChannels() ([]*Channel, error) {
	var channels []*Channel
	err := DB.
		Select("id", "type", "key", "status", "name", "channel_info").
		Where("type = ?", constant.ChannelTypeCodex).
		Order("id ASC").
		Find(&channels).Error
	return channels, err
}

func ListCodexMonitorEventLogs(
	channelIDs []int,
	fromInclusive int64,
	untilInclusive int64,
	afterCreatedAt int64,
	afterRequestID string,
	afterChannelID int,
	limit int,
) ([]CodexMonitorEventLog, bool, error) {
	if LOG_DB == nil {
		return nil, false, errors.New("log database is unavailable")
	}
	if len(channelIDs) == 0 || limit <= 0 {
		return []CodexMonitorEventLog{}, false, nil
	}

	query := LOG_DB.Model(&Log{}).
		Select("channel_id", "created_at", "request_id").
		Where("type = ?", LogTypeConsume).
		Where("channel_id IN ?", channelIDs).
		Where("request_id <> ''")
	query = excludeCodexMonitorChannelTestLogs(query).
		Where("created_at >= ? AND created_at <= ?", fromInclusive, untilInclusive)
	if afterCreatedAt > 0 {
		query = query.Where(
			"(created_at > ? OR (created_at = ? AND request_id > ?) OR (created_at = ? AND request_id = ? AND channel_id > ?))",
			afterCreatedAt,
			afterCreatedAt,
			afterRequestID,
			afterCreatedAt,
			afterRequestID,
			afterChannelID,
		)
	}

	rows := make([]CodexMonitorEventLog, 0, limit+1)
	if err := query.Order("created_at ASC").Order("request_id ASC").Order("channel_id ASC").Limit(limit + 1).Find(&rows).Error; err != nil {
		return nil, false, err
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	return rows, hasMore, nil
}

func OldestCodexMonitorEventTimestamp(channelIDs []int) (int64, bool, error) {
	if LOG_DB == nil {
		return 0, false, errors.New("log database is unavailable")
	}
	if len(channelIDs) == 0 {
		return 0, false, nil
	}

	var result CodexMonitorEventLog
	tx := LOG_DB.Model(&Log{}).
		Select("channel_id", "created_at", "request_id").
		Where("type = ?", LogTypeConsume).
		Where("channel_id IN ?", channelIDs).
		Where("request_id <> ''")
	tx = excludeCodexMonitorChannelTestLogs(tx).
		Order("created_at ASC").Order("request_id ASC").Order("channel_id ASC").
		Limit(1).
		Take(&result)
	if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return 0, false, nil
	}
	if tx.Error != nil {
		return 0, false, tx.Error
	}
	return result.CreatedAt, result.CreatedAt > 0, nil
}

func excludeCodexMonitorChannelTestLogs(query *gorm.DB) *gorm.DB {
	if common.UsingLogDatabase(common.DatabaseTypeMySQL) {
		// MySQL 5.7 installations may retain a latin1 log column even when the
		// client connection uses utf8mb4. Binary comparison avoids an illegal
		// mix-of-collations error without changing the stored log schema.
		return query.Where("(content IS NULL OR CAST(content AS BINARY) <> CAST(? AS BINARY))", codexMonitorChannelTestLogContent)
	}
	return query.Where("(content IS NULL OR content <> ?)", codexMonitorChannelTestLogContent)
}

func CodexMonitorEventSourceAvailable() bool {
	return common.LogConsumeEnabled && LOG_DB != nil
}
