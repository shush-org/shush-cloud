package models

import (
	"errors"
	"time"
)

// Scope represents a scope within a project for managing secrets.
type Scope struct {
	ID              int64     `json:"id" db:"id"`
	ProjectID       int64     `json:"project_id" db:"project_id"`
	Name            *string   `json:"name" db:"name"`                           // Nullable for optional name
	SymmetricKeyEnc *string   `json:"symmetric_key_enc" db:"symmetric_key_enc"` // Nullable for optional key
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// Validate ensures Scope fields are valid.
func (s *Scope) Validate() error {
	if s.ProjectID == 0 {
		return errors.New("project_id is required")
	}
	if s.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return nil
}

// ScopeConfig represents the configuration for a scope within a project.
type ScopeConfig struct {
	Name    string         `json:"name"`
	Remote  string         `json:"remote"`
	Secrets []SecretConfig `json:"secrets"`
}

// CreateScopeRequest represents a request to create a new scope.
type CreateScopeRequest struct {
	ProjectID int64  `json:"project_id"`
	Name      string `json:"name"`
}

// ScopeAccess represents access permissions for a scope.
type ScopeAccess struct {
	ID          int64     `json:"id" db:"id"`
	ScopeID     int64     `json:"scope_id" db:"scope_id"`
	TeamID      *int64    `json:"team_id" db:"team_id"`
	UserID      *int64    `json:"user_id" db:"user_id"`
	AccessLevel string    `json:"access_level" db:"access_level"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// GrantAccessRequest represents a request to grant access to a scope.
type GrantAccessRequest struct {
	ScopeID     int64  `json:"scope_id"`
	TeamID      *int64 `json:"team_id,omitempty"`
	UserID      *int64 `json:"user_id,omitempty"`
	AccessLevel string `json:"access_level"`
}
