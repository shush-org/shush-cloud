package models

import (
	"errors"
	"time"
)

// Device represents a user's device, used for authentication and cleanup of inactive devices.
type Device struct {
	ID               int64     `json:"id" db:"id"`
	UserID           int64     `json:"user_id" db:"user_id"`
	DeviceIdentifier *string   `json:"device_identifier" db:"device_identifier"`
	PublicKey        string    `json:"public_key" db:"public_key"`
	LastUsedAt       time.Time `json:"last_used_at" db:"last_used_at"` // Used by CleanupService to remove inactive devices
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}

// Validate ensures Device fields are valid.
func (d *Device) Validate() error {
	if d.UserID == 0 {
		return errors.New("user_id is required")
	}
	if d.PublicKey == "" {
		return errors.New("public_key is required")
	}
	if d.LastUsedAt.IsZero() {
		return errors.New("last_used_at is required")
	}
	if d.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return nil
}

// DeviceLoginRequest represents a request for device login.
type DeviceLoginRequest struct {
	DeviceIdentifier string `json:"device_identifier"`
	PublicKey        string `json:"public_key"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IdToken          string `json:"id_token"` // Standardized to camelCase
}

// DeviceLoginResponse represents the response after a successful device login.
type DeviceLoginResponse struct {
	DeviceID    int64  `json:"device_id"`
	AccessToken string `json:"access_token"` // Maps to UserToken.Token
	User        User   `json:"user"`
}

// UserToken represents an authentication token for a device.
type UserToken struct {
	ID        int64     `json:"id" db:"id"`
	DeviceID  int64     `json:"device_id" db:"device_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"` // Used by CleanupService to remove expired tokens
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Validate ensures UserToken fields are valid.
func (t *UserToken) Validate() error {
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
