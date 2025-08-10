package models

import (
	"errors"
	"time"
)

// Team represents a team associated with a project.
type Team struct {
	ID        int64     `json:"id" db:"id"`
	ProjectID int64     `json:"project_id" db:"project_id"`
	Name      *string   `json:"name" db:"name"` // Nullable for optional name
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Validate ensures Team fields are valid.
func (t *Team) Validate() error {
	if t.ProjectID == 0 {
		return errors.New("project_id is required")
	}
	if t.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return nil
}

// TeamMember represents a user's membership in a team.
type TeamMember struct {
	ID        int64     `json:"id" db:"id"`
	TeamID    int64     `json:"team_id" db:"team_id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	Role      string    `json:"role" db:"role"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
