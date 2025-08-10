package handlers

import (
	"database/sql"
	"github.com/shush-org/shush-cloud/internal/config"
	"time"
)

type Handlers struct {
	db     *sql.DB
	config *config.Config
}

func New(db *sql.DB, cfg *config.Config) *Handlers {
	return &Handlers{
		db:     db,
		config: cfg,
	}
}

// GetConfig returns the configuration (useful for handlers that need config values)
func (h *Handlers) GetConfig() *config.Config {
	return h.config
}

// GetTokenDurations returns the configured token durations
func (h *Handlers) GetTokenDurations() (deviceTokenDuration, refreshTokenDuration time.Duration) {
	if h.config != nil {
		return h.config.DeviceTokenDuration, h.config.RefreshTokenDuration
	}
	// Fallback to default values if config is nil
	return 30 * 24 * time.Hour, 90 * 24 * time.Hour
}
