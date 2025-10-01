package models

import (
	"time"

	"github.com/google/uuid"
)

// Commit represents a commit of secrets in a scope.
type Commit struct {
	ID        uuid.UUID `json:"id" db:"id"`
	ScopeID   int64     `json:"scope_id" db:"scope_id"`
	AuthorID  int64     `json:"author_id" db:"author_id"`
	Message   *string   `json:"message" db:"message"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// CommitSecretsRequest represents a request to commit secrets in a scope.
type CommitSecretsRequest struct {
	ScopeID   int64   `json:"scope_id"`
	AuthorID  int64   `json:"author_id"`
	Message   *string `json:"message"`
	SecretIDs []int64 `json:"secret_ids"`
}
