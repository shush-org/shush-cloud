package middlewares

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	db *sql.DB
}

type AuthResult struct {
	UserID   int64
	DeviceID int64
	Valid    bool
	Error    string
}

func NewAuthMiddleware(db *sql.DB) *AuthMiddleware {
	return &AuthMiddleware{db: db}
}

// RequireAuth enforces authentication
func (am *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		result := am.authenticateRequest(c)

		if !result.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": result.Error,
				"code":  "AUTHENTICATION_REQUIRED",
			})
			c.Abort()
			return
		}

		// Set context values
		c.Set("user_id", result.UserID)
		c.Set("device_id", result.DeviceID)
		c.Set("authenticated", true)

		c.Next()
	}
}

// OptionalAuth allows but doesn't require authentication
func (am *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		result := am.authenticateRequest(c)

		if result.Valid {
			c.Set("user_id", result.UserID)
			c.Set("device_id", result.DeviceID)
			c.Set("authenticated", true)
		} else {
			c.Set("authenticated", false)
		}

		c.Next()
	}
}

// authenticateRequest handles the core authentication logic
func (am *AuthMiddleware) authenticateRequest(c *gin.Context) *AuthResult {
	// Extract authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return &AuthResult{
			Valid: false,
			Error: "Authorization header required",
		}
	}

	// Parse Bearer token
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return &AuthResult{
			Valid: false,
			Error: "Invalid authorization format. Expected 'Bearer <token>'",
		}
	}

	token := tokenParts[1]
	if token == "" {
		return &AuthResult{
			Valid: false,
			Error: "Empty authorization token",
		}
	}

	// Validate token against database
	return am.validateToken(token, c.ClientIP())
}

// validateToken checks the token against the database
func (am *AuthMiddleware) validateToken(token, clientIP string) *AuthResult {
	var userID, deviceID int64
	var lastUsedAt time.Time
	var deviceIdentifier sql.NullString

	log.Printf("Validating token: %s, client_ip: %s", token, clientIP)

	query := `
        SELECT d.user_id, d.id, d.device_identifier, d.last_used_at
        FROM devices d 
        JOIN device_tokens dt ON dt.device_id = d.id
        WHERE dt.token = $1 AND dt.expires_at > NOW()`

	err := am.db.QueryRow(query, token).Scan(&userID, &deviceID, &deviceIdentifier, &lastUsedAt)
	if err == sql.ErrNoRows {
		log.Printf("Token validation failed: token=%s, reason=no rows found (expired or invalid)", token)
		return &AuthResult{
			Valid: false,
			Error: "Invalid or expired token",
		}
	}
	if err != nil {
		log.Printf("Database error during token validation for token=%s: %v", token, err)
		return &AuthResult{
			Valid: false,
			Error: "Authentication failed",
		}
	}

	// Check if device access should be restricted (e.g., too old)
	if time.Since(lastUsedAt) > 90*24*time.Hour { // 90 days
		log.Printf("Device %d hasn't been used for %v, requiring re-authentication", deviceID, time.Since(lastUsedAt))
		return &AuthResult{
			Valid: false,
			Error: "Device authentication expired, please login again",
		}
	}

	log.Printf("Token validated successfully: user_id=%d, device_id=%d, device_identifier=%s", userID, deviceID, deviceIdentifier.String)
	go am.updateDeviceActivity(deviceID, clientIP)

	return &AuthResult{
		Valid:    true,
		UserID:   userID,
		DeviceID: deviceID,
	}
}

// updateDeviceActivity updates device last used timestamp and IP
func (am *AuthMiddleware) updateDeviceActivity(deviceID int64, clientIP string) {
	updateQuery := `
		UPDATE devices 
		SET last_used_at = NOW(), last_ip = $2 
		WHERE id = $1`

	if _, err := am.db.Exec(updateQuery, deviceID, clientIP); err != nil {
		log.Printf("Failed to update device activity for device_id=%d: %v", deviceID, err)
	}
}

// RevokeDeviceToken revokes a specific device token
func (am *AuthMiddleware) RevokeDeviceToken(deviceID int64) error {
	_, err := am.db.Exec(`
		DELETE FROM device_tokens WHERE device_id = $1;
		DELETE FROM user_tokens WHERE device_id = $1;
	`, deviceID)

	if err != nil {
		return err
	}

	log.Printf("Revoked tokens for device_id=%d", deviceID)
	return nil
}

// RevokeUserTokens revokes all tokens for a user
func (am *AuthMiddleware) RevokeUserTokens(userID int64) error {
	_, err := am.db.Exec(`
		DELETE FROM device_tokens 
		WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1);
		
		DELETE FROM user_tokens 
		WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1);
	`, userID)

	if err != nil {
		return err
	}

	log.Printf("Revoked all tokens for user_id=%d", userID)
	return nil
}

// CleanupExpiredTokens removes expired tokens from the database
func (am *AuthMiddleware) CleanupExpiredTokens() error {
	result, err := am.db.Exec(`
		DELETE FROM device_tokens WHERE expires_at <= NOW();
		DELETE FROM user_tokens WHERE expires_at <= NOW();
	`)

	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("Cleaned up %d expired tokens", rowsAffected)
	}

	return nil
}

// GetAuthenticatedUser helper function for handlers
func GetAuthenticatedUser(c *gin.Context) (userID, deviceID int64, ok bool) {
	userIDVal, userExists := c.Get("user_id")
	deviceIDVal, deviceExists := c.Get("device_id")
	authenticated, authExists := c.Get("authenticated")

	if !userExists || !deviceExists || !authExists {
		return 0, 0, false
	}

	if isAuth, ok := authenticated.(bool); !ok || !isAuth {
		return 0, 0, false
	}

	userID, userOk := userIDVal.(int64)
	deviceID, deviceOk := deviceIDVal.(int64)

	return userID, deviceID, userOk && deviceOk
}

// RequireUserID middleware that ensures the user can only access their own resources
func (am *AuthMiddleware) RequireUserID() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _, ok := GetAuthenticatedUser(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		// Check if the user is trying to access their own resources
		requestedUserID := c.Param("id")
		if requestedUserID == "" {
			requestedUserID = c.Param("userId")
		}

		if requestedUserID != "" && requestedUserID != fmt.Sprintf("%d", userID) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied: can only access your own resources",
				"code":  "INSUFFICIENT_PERMISSIONS",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
