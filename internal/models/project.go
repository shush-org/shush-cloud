package models

import (
	"errors"
	"time"
)

// Project represents a project owned by a user.
type Project struct {
	ID        int64     `json:"id" db:"id"`
	OwnerID   int64     `json:"owner_id" db:"owner_id"`
	Name      *string   `json:"name" db:"name"` // Nullable for optional name
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Validate ensures Project fields are valid.
func (p *Project) Validate() error {
	if p.OwnerID == 0 {
		return errors.New("owner_id is required")
	}
	if p.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return nil
}

// ProjectConfig represents the configuration for a project.
type ProjectConfig struct {
	Version     string                 `json:"version"`
	ProjectName string                 `json:"project_name"`
	Scopes      map[string]ScopeConfig `json:"scopes"`
}

// InitProjectRequest represents a request to initialize a new project.
type InitProjectRequest struct {
	Name string `json:"name"`
}
