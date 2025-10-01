package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL    string
	JWTSecret      string
	Port           string
	OAuthIssuerUrl string

	// Token configuration
	DeviceTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	OAuthTokenBuffer     time.Duration

	// Security settings
	MaxDevicesPerUser    int
	TokenCleanupInterval time.Duration
	AuditLogRetention    time.Duration
	FailedLoginRetention time.Duration
	InactiveDeviceCutoff time.Duration

	// Rate limiting
	EnableRateLimit   bool
	RateLimitRequests int
	RateLimitWindow   time.Duration
}

func Load() *Config {
	return &Config{
		DatabaseURL:    getEnv("DATABASE_URL", ""),
		JWTSecret:      getEnv("JWT_SECRET", ""),
		Port:           getEnv("PORT", "8080"),
		OAuthIssuerUrl: getEnv("OAUTH_ISSUER", ""),

		// Token durations
		DeviceTokenDuration:  getDurationEnv("DEVICE_TOKEN_DURATION", 30*24*time.Hour),  // 30 days
		RefreshTokenDuration: getDurationEnv("REFRESH_TOKEN_DURATION", 90*24*time.Hour), // 90 days
		OAuthTokenBuffer:     getDurationEnv("OAUTH_TOKEN_BUFFER", 5*time.Minute),       // Refresh 5 min before expiry

		// Security settings
		MaxDevicesPerUser:    getIntEnv("MAX_DEVICES_PER_USER", 2),
		TokenCleanupInterval: getDurationEnv("TOKEN_CLEANUP_INTERVAL", 24*time.Hour),
		AuditLogRetention:    getDurationEnv("AUDIT_LOG_RETENTION", 90*24*time.Hour),
		FailedLoginRetention: getDurationEnv("FAILED_LOGIN_RETENTION", 30*24*time.Hour),
		InactiveDeviceCutoff: getDurationEnv("INACTIVE_DEVICE_CUTOFF", 365*24*time.Hour),

		// Rate limiting
		EnableRateLimit:   getBoolEnv("ENABLE_RATE_LIMIT", true),
		RateLimitRequests: getIntEnv("RATE_LIMIT_REQUESTS", 100),
		RateLimitWindow:   getDurationEnv("RATE_LIMIT_WINDOW", time.Hour),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	if defaultValue == "" {
		log.Fatalf("Environment variable %s is required", key)
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
		log.Printf("Warning: Invalid integer value for %s, using default %d", key, defaultValue)
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
		log.Printf("Warning: Invalid boolean value for %s, using default %v", key, defaultValue)
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
		log.Printf("Warning: Invalid duration value for %s, using default %v", key, defaultValue)
	}
	return defaultValue
}
