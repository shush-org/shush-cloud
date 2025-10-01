package models

import (
	"errors"
	"time"
)

// Secret represents an encrypted secret within a scope.
type Secret struct {
	ID        int64     `json:"id" db:"id"`
	ScopeID   int64     `json:"scope_id" db:"scope_id"`
	Key       string    `json:"key" db:"key"`
	ValueEnc  string    `json:"value_enc" db:"value_enc"`
	Format    string    `json:"format" db:"format"`
	CreatedBy int64     `json:"created_by" db:"created_by"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Validate ensures Secret fields are valid.
func (s *Secret) Validate() error {
	if s.ScopeID == 0 {
		return errors.New("scope_id is required")
	}
	if s.Key == "" {
		return errors.New("key is required")
	}
	if s.ValueEnc == "" {
		return errors.New("value_enc is required")
	}
	if s.CreatedBy == 0 {
		return errors.New("created_by is required")
	}
	if s.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return nil
}

// SecretConfig represents the configuration for a secret.
type SecretConfig struct {
	Path   string `json:"path"`
	Format string `json:"format"`
}

// AddSecretRequest represents a request to add a new secret to a scope.
type AddSecretRequest struct {
	ScopeID   int64  `json:"scope_id"`
	Key       string `json:"key"`
	Value     string `json:"value"` // Will be encrypted before storing
	Format    string `json:"format"`
	CreatedBy int64  `json:"created_by"`
}
