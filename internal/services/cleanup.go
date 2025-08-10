package services

import (
	"database/sql"
	"log"
	"strings"
	"time"
)

type CleanupService struct {
	db     *sql.DB
	config *CleanupConfig
	ticker *time.Ticker
	done   chan bool
}

type CleanupConfig struct {
	TokenCleanupInterval time.Duration
	AuditLogRetention    time.Duration
	MaxDevicesPerUser    int
	FailedLoginRetention time.Duration
	InactiveDeviceCutoff time.Duration
}

func NewCleanupService(db *sql.DB, config *CleanupConfig) *CleanupService {
	return &CleanupService{
		db:     db,
		config: config,
		done:   make(chan bool),
	}
}

// Start begins the cleanup service
func (cs *CleanupService) Start() {
	log.Printf("Starting cleanup service with interval: %v", cs.config.TokenCleanupInterval)

	// Run cleanup immediately on start
	cs.runCleanup()

	// Set up ticker for periodic cleanup
	cs.ticker = time.NewTicker(cs.config.TokenCleanupInterval)

	go func() {
		for {
			select {
			case <-cs.ticker.C:
				cs.runCleanup()
			case <-cs.done:
				return
			}
		}
	}()
}

// Stop stops the cleanup service
func (cs *CleanupService) Stop() {
	log.Println("Stopping cleanup service")
	if cs.ticker != nil {
		cs.ticker.Stop()
	}
	cs.done <- true
}

// runCleanup performs all cleanup tasks
func (cs *CleanupService) runCleanup() {
	log.Println("Running periodic cleanup...")

	// Clean up expired tokens
	if deletedTokens, err := cs.cleanupExpiredTokens(); err != nil {
		log.Printf("Error cleaning up expired tokens: %v", err)
	} else if deletedTokens > 0 {
		log.Printf("Cleaned up %d expired tokens", deletedTokens)
	}

	// Clean up old audit logs
	if deletedLogs, err := cs.cleanupOldAuditLogs(); err != nil {
		log.Printf("Error cleaning up old audit logs: %v", err)
	} else if deletedLogs > 0 {
		log.Printf("Cleaned up %d old audit log entries", deletedLogs)
	}

	// Clean up old failed login attempts
	if deletedAttempts, err := cs.cleanupFailedLoginAttempts(); err != nil {
		log.Printf("Error cleaning up failed login attempts: %v", err)
	} else if deletedAttempts > 0 {
		log.Printf("Cleaned up %d old failed login attempts", deletedAttempts)
	}

	// Clean up devices that haven't been used in a very long time
	if deletedDevices, err := cs.cleanupInactiveDevices(); err != nil {
		log.Printf("Error cleaning up inactive devices: %v", err)
	} else if deletedDevices > 0 {
		log.Printf("Cleaned up %d inactive devices", deletedDevices)
	}

	// Enforce device limits per user
	if enforcedUsers, err := cs.enforceDeviceLimits(); err != nil {
		log.Printf("Error enforcing device limits: %v", err)
	} else if enforcedUsers > 0 {
		log.Printf("Enforced device limits for %d users", enforcedUsers)
	}
}

// cleanupExpiredTokens removes expired tokens
func (cs *CleanupService) cleanupExpiredTokens() (int, error) {
	var totalDeleted int

	// Clean up expired device tokens (separate transaction)
	result1, err := cs.db.Exec("DELETE FROM device_tokens WHERE expires_at <= NOW()")
	if err != nil {
		log.Printf("Error cleaning device tokens: %v", err)
	} else {
		if rows, _ := result1.RowsAffected(); rows > 0 {
			totalDeleted += int(rows)
			log.Printf("Cleaned up %d expired device tokens", rows)
		}
	}

	// Clean up expired user tokens (separate transaction)
	result2, err := cs.db.Exec("DELETE FROM user_tokens WHERE expires_at <= NOW()")
	if err != nil {
		log.Printf("Error cleaning user tokens: %v", err)
	} else {
		if rows, _ := result2.RowsAffected(); rows > 0 {
			totalDeleted += int(rows)
			log.Printf("Cleaned up %d expired user tokens", rows)
		}
	}

	// Clean up expired device sessions if the table exists (separate transaction)
	result3, err := cs.db.Exec("DELETE FROM device_sessions WHERE expires_at <= NOW() OR active = false")
	if err != nil && !isTableNotExistError(err) {
		log.Printf("Error cleaning device sessions: %v", err)
	} else if err == nil {
		if rows, _ := result3.RowsAffected(); rows > 0 {
			totalDeleted += int(rows)
			log.Printf("Cleaned up %d expired device sessions", rows)
		}
	}

	return totalDeleted, nil
}

// cleanupOldAuditLogs removes old audit log entries
func (cs *CleanupService) cleanupOldAuditLogs() (int, error) {
	cutoffTime := time.Now().Add(-cs.config.AuditLogRetention)

	result, err := cs.db.Exec(`
		DELETE FROM audit_logs 
		WHERE created_at < $1
	`, cutoffTime)

	if err != nil {
		// Table might not exist in older schemas
		if isTableNotExistError(err) {
			return 0, nil
		}
		return 0, err
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// cleanupFailedLoginAttempts removes old failed login attempts
func (cs *CleanupService) cleanupFailedLoginAttempts() (int, error) {
	cutoffTime := time.Now().Add(-cs.config.FailedLoginRetention)

	result, err := cs.db.Exec(`
		DELETE FROM failed_login_attempts 
		WHERE created_at < $1
	`, cutoffTime)

	if err != nil {
		// Table might not exist in older schemas
		if isTableNotExistError(err) {
			return 0, nil
		}
		return 0, err
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// cleanupInactiveDevices removes devices that haven't been used for the configured duration
func (cs *CleanupService) cleanupInactiveDevices() (int, error) {
	cutoffTime := time.Now().Add(-cs.config.InactiveDeviceCutoff)

	tx, err := cs.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// First, delete associated tokens
	_, err = tx.Exec(`
		DELETE FROM device_tokens 
		WHERE device_id IN (
			SELECT id FROM devices 
			WHERE last_used_at < $1
		)
	`, cutoffTime)
	if err != nil {
		return 0, err
	}

	_, err = tx.Exec(`
		DELETE FROM user_tokens 
		WHERE device_id IN (
			SELECT id FROM devices 
			WHERE last_used_at < $1
		)
	`, cutoffTime)
	if err != nil {
		return 0, err
	}

	// Then delete the devices themselves
	result, err := tx.Exec(`
		DELETE FROM devices 
		WHERE last_used_at < $1
	`, cutoffTime)
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// enforceDeviceLimits ensures users don't have too many devices
func (cs *CleanupService) enforceDeviceLimits() (int, error) {
	// Get users with too many devices
	query := `
		SELECT user_id, COUNT(*) as device_count
		FROM devices
		GROUP BY user_id
		HAVING COUNT(*) > $1
	`

	rows, err := cs.db.Query(query, cs.config.MaxDevicesPerUser)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	enforcedUsers := 0

	for rows.Next() {
		var userID int64
		var deviceCount int

		if err := rows.Scan(&userID, &deviceCount); err != nil {
			continue
		}

		// Remove oldest devices for this user, keeping only the max allowed
		devicesToRemove := deviceCount - cs.config.MaxDevicesPerUser

		if err := cs.removeOldestDevices(userID, devicesToRemove); err != nil {
			log.Printf("Failed to remove oldest devices for user %d: %v", userID, err)
			continue
		}

		enforcedUsers++
		log.Printf("Removed %d oldest devices for user %d (had %d, max %d)",
			devicesToRemove, userID, deviceCount, cs.config.MaxDevicesPerUser)
	}

	return enforcedUsers, nil
}

// removeOldestDevices removes the oldest devices for a user
func (cs *CleanupService) removeOldestDevices(userID int64, count int) error {
	tx, err := cs.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Get the IDs of the oldest devices
	deviceQuery := `
		SELECT id FROM devices 
		WHERE user_id = $1 
		ORDER BY last_used_at ASC 
		LIMIT $2
	`

	rows, err := tx.Query(deviceQuery, userID, count)
	if err != nil {
		return err
	}
	defer rows.Close()

	var deviceIDs []int64
	for rows.Next() {
		var deviceID int64
		if err := rows.Scan(&deviceID); err != nil {
			continue
		}
		deviceIDs = append(deviceIDs, deviceID)
	}
	rows.Close()

	// Remove tokens and devices
	for _, deviceID := range deviceIDs {
		// Remove tokens first
		_, err = tx.Exec("DELETE FROM device_tokens WHERE device_id = $1", deviceID)
		if err != nil {
			return err
		}

		_, err = tx.Exec("DELETE FROM user_tokens WHERE device_id = $1", deviceID)
		if err != nil {
			return err
		}

		// Remove device
		_, err = tx.Exec("DELETE FROM devices WHERE id = $1", deviceID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// isTableNotExistError checks if the error is due to a table not existing
func isTableNotExistError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "does not exist") ||
		strings.Contains(err.Error(), "doesn't exist") ||
		strings.Contains(err.Error(), "no such table"))
}

// GetCleanupStats returns statistics about what would be cleaned up
func (cs *CleanupService) GetCleanupStats() (*CleanupStats, error) {
	stats := &CleanupStats{}

	// Count expired tokens
	err := cs.db.QueryRow(`
		SELECT 
			(SELECT COUNT(*) FROM device_tokens WHERE expires_at <= NOW()) +
			(SELECT COUNT(*) FROM user_tokens WHERE expires_at <= NOW())
	`).Scan(&stats.ExpiredTokens)
	if err != nil {
		return nil, err
	}

	// Count old audit logs
	cutoffTime := time.Now().Add(-cs.config.AuditLogRetention)
	err = cs.db.QueryRow(`
		SELECT COUNT(*) FROM audit_logs WHERE created_at < $1
	`, cutoffTime).Scan(&stats.OldAuditLogs)
	if err != nil && !isTableNotExistError(err) {
		return nil, err
	}

	// Count inactive devices
	cutoffTime = time.Now().Add(-cs.config.InactiveDeviceCutoff)
	err = cs.db.QueryRow(`
		SELECT COUNT(*) FROM devices WHERE last_used_at < $1
	`, cutoffTime).Scan(&stats.InactiveDevices)
	if err != nil {
		return nil, err
	}

	// Count users over device limit
	err = cs.db.QueryRow(`
		SELECT COUNT(*)
		FROM (
			SELECT user_id, COUNT(*) as device_count
			FROM devices
			GROUP BY user_id
			HAVING COUNT(*) > $1
		) as over_limit_users
	`, cs.config.MaxDevicesPerUser).Scan(&stats.UsersOverDeviceLimit)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

type CleanupStats struct {
	ExpiredTokens        int `json:"expired_tokens"`
	OldAuditLogs         int `json:"old_audit_logs"`
	InactiveDevices      int `json:"inactive_devices"`
	UsersOverDeviceLimit int `json:"users_over_device_limit"`
}
