package models

import (
	"errors"
	"time"
)

// FailedLoginAttempt represents a failed login attempt, used by CleanupService.
type FailedLoginAttempt struct {
	ID        int64     `json:"id" db:"id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"` // Used by CleanupService to remove old attempts
}

// Validate ensures FailedLoginAttempt fields are valid.
func (f *FailedLoginAttempt) Validate() error {
	if f.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return nil
}

// DeviceToken represents a token for a device, used by CleanupService.
type DeviceToken struct {
	ID        int64     `json:"id" db:"id"`
	DeviceID  int64     `json:"device_id" db:"device_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"` // Used by CleanupService to remove expired tokens
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Validate ensures DeviceToken fields are valid.
func (t *DeviceToken) Validate() error {
	if t.DeviceID == 0 {
		return errors.New("device_id is required")
	}
	if t.Token == "" {
		return errors.New("token is required")
	}
	if t.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	if t.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return nil
}

// AuditLog represents an audit log entry, used by CleanupService.
type AuditLog struct {
	ID        int64     `json:"id" db:"id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"` // Used by CleanupService to remove old logs
	Action    string    `json:"action" db:"action"`         // Describes the action logged
	UserID    *int64    `json:"user_id" db:"user_id"`       // Nullable user ID associated with the action
}

// Validate ensures AuditLog fields are valid.
func (a *AuditLog) Validate() error {
	if a.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	if a.Action == "" {
		return errors.New("action is required")
	}
	return nil
}
