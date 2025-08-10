package models

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// User represents a user in the system, linked to OAuth authentication.
type User struct {
	ID            int64     `json:"id" db:"id"`
	OAuthSub      string    `json:"oauth_sub" db:"oauth_sub"`
	Email         string    `json:"email" db:"email"`
	Name          *string   `json:"name" db:"name"`
	EmailVerified bool      `json:"email_verified" db:"email_verified"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// Validate ensures User fields are valid.
func (u *User) Validate() error {
	if u.OAuthSub == "" {
		return errors.New("oauth_sub is required")
	}
	if u.Email == "" {
		return errors.New("email is required")
	}
	if u.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return nil
}

// IDTokenClaims represents claims in an OAuth ID token.
type IDTokenClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	jwt.RegisteredClaims
}
