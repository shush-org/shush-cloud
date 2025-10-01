package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/shush-org/shush-cloud/internal/models"
)

var (
	jwks            *keyfunc.JWKS
	jwksInitialized bool // Prevent double JWKS initialization
)

// Initialize JWKS by fetching the JWKS URI from Zitadel's OpenID Connect discovery document
func InitJWKS(oauthIssuerUrl string) error {
	if jwksInitialized {
		return nil
	}

	openIDConfigURL := oauthIssuerUrl + "/.well-known/openid-configuration"

	resp, err := http.Get(openIDConfigURL)
	if err != nil {
		return fmt.Errorf("failed to fetch OpenID configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid HTTP status code: %d", resp.StatusCode)
	}

	var discoveryResp struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discoveryResp); err != nil {
		return fmt.Errorf("failed to decode OpenID configuration: %w", err)
	}

	if discoveryResp.JWKSURI == "" {
		return errors.New("jwks_uri not found in OpenID configuration")
	}

	log.Printf("Fetching JWKS from: %s", discoveryResp.JWKSURI)

	jwks, err = keyfunc.Get(discoveryResp.JWKSURI, keyfunc.Options{
		RefreshInterval:   time.Hour,
		RefreshTimeout:    10 * time.Second,
		RefreshUnknownKID: true,
		RefreshErrorHandler: func(err error) {
			log.Printf("JWKS refresh error: %v", err)
		},
	})
	if err != nil {
		return fmt.Errorf("failed to initialize JWKS from %s: %w", discoveryResp.JWKSURI, err)
	}

	log.Printf("JWKS initialized successfully")
	jwksInitialized = true
	return nil
}

// getOAuthTokenDurations returns the configured token durations
func (h *Handlers) getOAuthTokenDurations() (deviceTokenDuration, refreshTokenDuration time.Duration) {
	if h.config != nil {
		return h.config.DeviceTokenDuration, h.config.RefreshTokenDuration
	}
	return 30 * 24 * time.Hour, 90 * 24 * time.Hour
}

// DeviceLogin handles CLI device authentication
func (h *Handlers) DeviceLogin(c *gin.Context) {
	var req models.DeviceLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	// Log the request (without sensitive data)
	log.Printf("DeviceLogin request from %s for device: %s", c.ClientIP(), req.DeviceIdentifier)

	// Validate request fields (Line 91)
	if req.IdToken == "" || req.RefreshToken == "" || req.DeviceIdentifier == "" || req.PublicKey == "" {
		log.Printf("Invalid DeviceLoginRequest: missing required fields")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required fields: id_token, refresh_token, device_identifier, and public_key are required",
			"code":  "MISSING_FIELDS",
		})
		return
	}

	// Sanitize inputs
	if strings.ContainsRune(req.DeviceIdentifier, 0) {
		log.Printf("Invalid DeviceLoginRequest: device_identifier contains null bytes")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid characters in device_identifier",
			"code":  "INVALID_INPUT",
		})
		return
	}
	if strings.ContainsRune(req.PublicKey, 0) {
		log.Printf("Invalid DeviceLoginRequest: public_key contains null bytes")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid characters in public_key",
			"code":  "INVALID_INPUT",
		})
		return
	}

	// Validate and normalize public key
	if err := h.validateAndNormalizePublicKey(&req.PublicKey); err != nil {
		log.Printf("Invalid public key from %s: %v", c.ClientIP(), err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid public key format",
			"code":  "INVALID_PUBLIC_KEY",
		})
		return
	}

	// Verify ID token (Line ~129)
	claims, err := verifyIDToken(req.IdToken)
	if err != nil {
		log.Printf("ID token verification failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid ID token",
			"code":  "INVALID_ID_TOKEN",
		})
		return
	}

	log.Printf("Verified ID token for user: %s", claims.Email)

	// Begin transaction for atomicity
	tx, err := h.db.Begin()
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal server error",
			"code":  "DATABASE_ERROR",
		})
		return
	}
	defer tx.Rollback()

	// Get or create user
	user, err := h.getOrCreateUser(tx, claims)
	if err != nil {
		log.Printf("Failed to get or create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to process user",
			"code":  "USER_ERROR",
		})
		return
	}

	// Validate user
	if err := user.Validate(); err != nil {
		log.Printf("Invalid user data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user data",
			"code":  "USER_VALIDATION_ERROR",
		})
		return
	}

	// Register or update device
	device, err := h.registerOrUpdateDevice(tx, user.ID, req.DeviceIdentifier, req.PublicKey, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		log.Printf("Failed to register device: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to register device",
			"code":  "DEVICE_ERROR",
		})
		return
	}

	// Validate device
	if err := device.Validate(); err != nil {
		log.Printf("Invalid device data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid device data",
			"code":  "DEVICE_VALIDATION_ERROR",
		})
		return
	}

	// Store refresh token with configurable expiration
	_, refreshTokenDuration := h.getOAuthTokenDurations()
	refreshTokenExpiry := time.Now().Add(refreshTokenDuration)
	refreshToken := models.UserToken{
		DeviceID:  device.ID,
		Token:     req.RefreshToken,
		ExpiresAt: refreshTokenExpiry,
		CreatedAt: time.Now(),
	}
	if err := refreshToken.Validate(); err != nil {
		log.Printf("Invalid refresh token data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid refresh token data",
			"code":  "TOKEN_VALIDATION_ERROR",
		})
		return
	}
	if err := h.storeRefreshToken(tx, device.ID, req.RefreshToken, refreshTokenExpiry); err != nil {
		log.Printf("Failed to store refresh token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to store refresh token",
			"code":  "TOKEN_STORAGE_ERROR",
		})
		return
	}

	// Generate internal access token
	internalAccessToken, err := h.generateInternalToken()
	if err != nil {
		log.Printf("Failed to generate access token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate access token",
			"code":  "TOKEN_GENERATION_ERROR",
		})
		return
	}

	// Store internal token with configurable expiration
	deviceOAuthTokenDuration, _ := h.getOAuthTokenDurations()
	oAuthTokenExpiry := time.Now().Add(deviceOAuthTokenDuration)
	accessToken := models.DeviceToken{
		DeviceID:  device.ID,
		Token:     internalAccessToken,
		ExpiresAt: oAuthTokenExpiry,
		CreatedAt: time.Now(),
	}
	if err := accessToken.Validate(); err != nil {
		log.Printf("Invalid access token data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid access token data",
			"code":  "TOKEN_VALIDATION_ERROR",
		})
		return
	}
	if err := h.storeInternalToken(tx, device.ID, internalAccessToken, oAuthTokenExpiry); err != nil {
		log.Printf("Failed to store internal token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to store access token",
			"code":  "TOKEN_STORAGE_ERROR",
		})
		return
	}

	// Log successful authentication
	if err := h.logAuditEvent(tx, user.ID, device.ID, "device_login", "device", device.ID, c.ClientIP(), c.GetHeader("User-Agent"), true, ""); err != nil {
		log.Printf("Failed to log audit event: %v", err)
		// Don't fail the request for audit logging issues
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to complete authentication",
			"code":  "COMMIT_ERROR",
		})
		return
	}

	response := models.DeviceLoginResponse{
		DeviceID:    device.ID,
		AccessToken: internalAccessToken,
		User:        *user,
	}

	log.Printf("Device login successful for user %s, device_id=%d", user.Email, device.ID)
	c.JSON(http.StatusOK, response)
}

// validateAndNormalizePublicKey validates and normalizes the public key
func (h *Handlers) validateAndNormalizePublicKey(publicKey *string) error {
	if publicKey == nil || *publicKey == "" {
		return fmt.Errorf("public key is empty")
	}

	// Remove any null bytes or invalid characters
	cleaned := strings.ReplaceAll(*publicKey, "\x00", "")
	if len(cleaned) != len(*publicKey) {
		log.Printf("Removed null bytes from public key")
	}

	// Try to decode as base64 first
	if decoded, err := base64.StdEncoding.DecodeString(cleaned); err == nil {
		if len(decoded) != 32 { // Ed25519 public key length
			return fmt.Errorf("invalid public key length: expected 32 bytes, got %d", len(decoded))
		}
		*publicKey = cleaned
		return nil
	}

	// If it's not base64, check if it's raw bytes
	if len(cleaned) == 32 {
		*publicKey = base64.StdEncoding.EncodeToString([]byte(cleaned))
		return nil
	}

	// Try URL-safe base64
	if decoded, err := base64.URLEncoding.DecodeString(cleaned); err == nil {
		if len(decoded) == 32 {
			*publicKey = base64.StdEncoding.EncodeToString(decoded)
			return nil
		}
	}

	return fmt.Errorf("invalid public key format: not valid base64 and wrong length (%d)", len(cleaned))
}

// getOrCreateUser gets an existing user or creates a new one
func (h *Handlers) getOrCreateUser(tx *sql.Tx, claims *models.IDTokenClaims) (*models.User, error) {
	var user models.User

	userQuery := `
		SELECT id, oauth_sub, email, name, email_verified, created_at, updated_at
		FROM users WHERE oauth_sub = $1`

	err := tx.QueryRow(userQuery, claims.Sub).Scan(
		&user.ID, &user.OAuthSub, &user.Email, &user.Name,
		&user.EmailVerified, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == nil {
		if user.EmailVerified != claims.EmailVerified {
			updateQuery := `UPDATE users SET email_verified = $1, updated_at = NOW() WHERE id = $2`
			if _, err := tx.Exec(updateQuery, claims.EmailVerified, user.ID); err != nil {
				return nil, fmt.Errorf("failed to update user email verification: %w", err)
			}
			user.EmailVerified = claims.EmailVerified
		}
		return &user, nil
	}

	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	createUserQuery := `
		INSERT INTO users (oauth_sub, email, name, email_verified)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`

	var namePtr *string
	if claims.Name != "" {
		namePtr = &claims.Name
	}

	err = tx.QueryRow(createUserQuery, claims.Sub, claims.Email, namePtr, claims.EmailVerified).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	user.OAuthSub = claims.Sub
	user.Email = claims.Email
	user.Name = namePtr
	user.EmailVerified = claims.EmailVerified

	return &user, nil
}

// registerOrUpdateDevice registers a new device or updates an existing one
func (h *Handlers) registerOrUpdateDevice(tx *sql.Tx, userID int64, deviceIdentifier, publicKey, clientIP, userAgent string) (*models.Device, error) {
	var device models.Device

	log.Printf("Registering device: user_id=%d, device_identifier='%s', public_key_len=%d, client_ip='%s'",
		userID, deviceIdentifier, len(publicKey), clientIP)

	deviceQuery := `
		INSERT INTO devices (user_id, device_identifier, public_key, last_used_at, last_ip, user_agent, platform)
		VALUES ($1, $2, $3, NOW(), $4, $5, 'cli')
		ON CONFLICT (user_id, device_identifier)
		DO UPDATE SET 
			public_key = $3, 
			last_used_at = NOW(),
			last_ip = $4,
			user_agent = $5,
			platform = 'cli'
		RETURNING id, user_id, device_identifier, public_key, last_used_at, created_at`

	err := tx.QueryRow(deviceQuery, userID, deviceIdentifier, publicKey, clientIP, userAgent).Scan(
		&device.ID, &device.UserID, &device.DeviceIdentifier, &device.PublicKey,
		&device.LastUsedAt, &device.CreatedAt,
	)
	if err != nil {
		log.Printf("Failed to register device: %v", err)
		return nil, fmt.Errorf("failed to register device: %w", err)
	}

	log.Printf("Successfully registered device with ID: %d", device.ID)
	return &device, nil
}

// storeRefreshToken stores the OAuth refresh token
func (h *Handlers) storeRefreshToken(tx *sql.Tx, deviceID int64, refreshToken string, expiresAt time.Time) error {
	query := `
		INSERT INTO user_tokens (device_id, token, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (device_id)
		DO UPDATE SET token = $2, expires_at = $3`

	_, err := tx.Exec(query, deviceID, refreshToken, expiresAt)
	return err
}

// storeInternalToken stores the internal API access token
func (h *Handlers) storeInternalToken(tx *sql.Tx, deviceID int64, token string, expiresAt time.Time) error {
	query := `
		INSERT INTO device_tokens (device_id, token, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (device_id)
		DO UPDATE SET token = $2, expires_at = $3`

	_, err := tx.Exec(query, deviceID, token, expiresAt)
	return err
}

// generateInternalToken generates a cryptographically secure random token
func (h *Handlers) generateInternalToken() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

// logAuditEvent logs an audit event
func (h *Handlers) logAuditEvent(tx *sql.Tx, userID, deviceID int64, action, resourceType string, resourceID int64, ipAddress, userAgent string, success bool, errorMsg string) error {
	query := `
		INSERT INTO audit_logs (user_id, device_id, action, resource_type, resource_id, ip_address, user_agent, success, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := tx.Exec(query, userID, deviceID, action, resourceType, resourceID, ipAddress, userAgent, success, errorMsg)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return err
	}
	return nil
}

// DeviceLogout handles CLI device logout with better cleanup
func (h *Handlers) DeviceLogout(c *gin.Context) {
	userID, deviceID, ok := getAuthenticatedUser(c)
	if !ok {
		log.Printf("DeviceLogout: user not authenticated, attempting to identify device")
		var req struct {
			DeviceID int64 `json:"device_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.DeviceID == 0 {
			log.Printf("DeviceLogout: no valid device_id provided in request body")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required or invalid device_id",
				"code":  "AUTHENTICATION_REQUIRED",
			})
			return
		}
		deviceID = req.DeviceID

		var exists bool
		err := h.db.QueryRow("SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)", deviceID).Scan(&exists)
		if err != nil || !exists {
			log.Printf("DeviceLogout: device_id=%d not found: %v", deviceID, err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid device_id",
				"code":  "INVALID_DEVICE",
			})
			return
		}
		err = h.db.QueryRow("SELECT user_id FROM devices WHERE id = $1", deviceID).Scan(&userID)
		if err != nil {
			log.Printf("DeviceLogout: failed to get user_id for device_id=%d: %v", deviceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Internal server error",
				"code":  "DATABASE_ERROR",
			})
			return
		}
	}

	log.Printf("DeviceLogout: processing logout for user_id=%d, device_id=%d", userID, deviceID)

	tx, err := h.db.Begin()
	if err != nil {
		log.Printf("DeviceLogout failed to begin transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal server error",
			"code":  "DATABASE_ERROR",
		})
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM device_tokens WHERE device_id = $1", deviceID)
	if err != nil {
		log.Printf("DeviceLogout failed to delete device_tokens for device_id=%d: %v", deviceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to logout",
			"code":  "LOGOUT_ERROR",
		})
		return
	}

	_, err = tx.Exec("DELETE FROM user_tokens WHERE device_id = $1", deviceID)
	if err != nil {
		log.Printf("DeviceLogout failed to delete user_tokens for device_id=%d: %v", deviceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to logout",
			"code":  "LOGOUT_ERROR",
		})
		return
	}

	if err := h.logAuditEvent(tx, userID, deviceID, "device_logout", "device", deviceID, c.ClientIP(), c.GetHeader("User-Agent"), true, ""); err != nil {
		log.Printf("Failed to log logout audit event: %v", err)
	}

	if err := tx.Commit(); err != nil {
		log.Printf("DeviceLogout failed to commit transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to complete logout",
			"code":  "COMMIT_ERROR",
		})
		return
	}

	log.Printf("DeviceLogout successful for user_id=%d, device_id=%d", userID, deviceID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
		"code":    "LOGOUT_SUCCESS",
	})
}

// ListUserDevices returns all devices for a user with enhanced information
func (h *Handlers) ListUserDevices(c *gin.Context) {
	userID, _, ok := getAuthenticatedUser(c)
	if !ok {
		log.Printf("ListUserDevices failed: user not authenticated")
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTHENTICATION_REQUIRED",
		})
		return
	}

	query := `
		SELECT 
			d.id, 
			d.user_id, 
			d.device_identifier, 
			d.last_used_at, 
			d.created_at,
			d.last_ip,
			d.user_agent,
			d.trusted,
			d.platform,
			dt.expires_at as token_expires_at,
			CASE WHEN dt.expires_at > NOW() THEN true ELSE false END as token_valid
		FROM devices d
		LEFT JOIN device_tokens dt ON d.id = dt.device_id
		WHERE d.user_id = $1
		ORDER BY d.last_used_at DESC`

	rows, err := h.db.Query(query, userID)
	if err != nil {
		log.Printf("ListUserDevices failed to query devices for user_id=%d: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get devices",
			"code":  "DATABASE_ERROR",
		})
		return
	}
	defer rows.Close()

	var devices []map[string]interface{}
	for rows.Next() {
		var device models.Device
		var lastIP, userAgent, platform sql.NullString
		var trusted sql.NullBool
		var tokenExpiresAt sql.NullTime
		var tokenValid bool

		err := rows.Scan(
			&device.ID, &device.UserID, &device.DeviceIdentifier,
			&device.LastUsedAt, &device.CreatedAt,
			&lastIP, &userAgent, &trusted, &platform, &tokenExpiresAt, &tokenValid,
		)
		if err != nil {
			log.Printf("ListUserDevices failed to scan device for user_id=%d: %v", userID, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to scan device",
				"code":  "SCAN_ERROR",
			})
			return
		}

		deviceInfo := map[string]interface{}{
			"id":                device.ID,
			"device_identifier": device.DeviceIdentifier,
			"last_used_at":      device.LastUsedAt,
			"created_at":        device.CreatedAt,
			"token_valid":       tokenValid,
		}

		if lastIP.Valid {
			deviceInfo["last_ip"] = lastIP.String
		}
		if userAgent.Valid {
			deviceInfo["user_agent"] = userAgent.String
		}
		if trusted.Valid {
			deviceInfo["trusted"] = trusted.Bool
		}
		if platform.Valid {
			deviceInfo["platform"] = platform.String
		}
		if tokenExpiresAt.Valid {
			deviceInfo["token_expires_at"] = tokenExpiresAt.Time
		}

		devices = append(devices, deviceInfo)
	}

	log.Printf("ListUserDevices successful for user_id=%d, found %d devices", userID, len(devices))
	c.JSON(http.StatusOK, gin.H{
		"devices": devices,
		"count":   len(devices),
	})
}

// Verify ID token from OAuth provider
func verifyIDToken(tokenString string) (*models.IDTokenClaims, error) {
	if jwks == nil {
		return nil, errors.New("JWKS not initialized")
	}

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &models.IDTokenClaims{})
	if err != nil {
		log.Printf("Failed to parse token header: %v", err)
	} else if kid, ok := token.Header["kid"].(string); ok {
		log.Printf("Token key ID (kid): %s", kid)
	}

	token, err = jwt.ParseWithClaims(tokenString, &models.IDTokenClaims{}, jwks.Keyfunc)
	if err != nil {
		log.Printf("Token verification failed: %v", err)
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(*models.IDTokenClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	log.Printf("Token verified successfully for user: %s", claims.Email)
	return claims, nil
}

// Helper function to get authenticated user from context
func getAuthenticatedUser(c *gin.Context) (userID, deviceID int64, ok bool) {
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
