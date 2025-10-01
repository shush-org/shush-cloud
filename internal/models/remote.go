package models

import "time"

// RemoteScope represents a remote repository for a scope.
type RemoteScope struct {
	ID        int64     `json:"id" db:"id"`
	ProjectID int64     `json:"project_id" db:"project_id"`
	Name      string    `json:"name" db:"name"`
	URL       string    `json:"url" db:"url"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// PushScopeRequest represents a request to push a scope to a remote.
type PushScopeRequest struct {
	ProjectID  int64  `json:"project_id"`
	ScopeID    int64  `json:"scope_id"`
	RemoteName string `json:"remote_name"`
}

// PullScopeRequest represents a request to pull a scope from a remote.
type PullScopeRequest struct {
	ProjectID  int64  `json:"project_id"`
	ScopeID    int64  `json:"scope_id"`
	RemoteName string `json:"remote_name"`
}
