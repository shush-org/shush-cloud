package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/shush-org/shush-cloud/internal/config"
	"github.com/shush-org/shush-cloud/internal/database"
	"github.com/shush-org/shush-cloud/internal/handlers"
	"github.com/shush-org/shush-cloud/internal/middlewares"
	"github.com/shush-org/shush-cloud/internal/routes"
	"github.com/shush-org/shush-cloud/internal/services"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Failed to load .env file: %v", err)
	} else {
		log.Println("Loaded .env file successfully")
	}

	// Log GIN_MODE for debugging
	log.Printf("GIN_MODE: %s", os.Getenv("GIN_MODE"))

	// Initialize configuration
	cfg := config.Load()
	log.Printf("Starting server with config: DeviceTokenDuration=%v, RefreshTokenDuration=%v",
		cfg.DeviceTokenDuration, cfg.RefreshTokenDuration)

	// Initialize database connection
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatal("Database ping failed:", err)
	}
	log.Println("Database connection established")

	// Initialize JWKS for JWT verification
	if err := handlers.InitJWKS(cfg.OAuthIssuerUrl); err != nil {
		log.Fatal("Failed to initialize JWKS:", err)
	}

	// Initialize cleanup service
	cleanupConfig := &services.CleanupConfig{
		TokenCleanupInterval: cfg.TokenCleanupInterval,
		AuditLogRetention:    cfg.AuditLogRetention,
		MaxDevicesPerUser:    cfg.MaxDevicesPerUser,
		FailedLoginRetention: cfg.FailedLoginRetention,
		InactiveDeviceCutoff: cfg.InactiveDeviceCutoff,
	}
	cleanupService := services.NewCleanupService(db, cleanupConfig)

	// Initialize Gin router
	switch os.Getenv("GIN_MODE") {
	case "release":
		gin.SetMode(gin.ReleaseMode)
	case "debug":
		gin.SetMode(gin.DebugMode)
	default:
		log.Printf("GIN_MODE not set or invalid (%s), defaulting to debug", os.Getenv("GIN_MODE"))
		gin.SetMode(gin.DebugMode)
	}
	r := gin.New()

	// Add middleware
	r.Use(middlewares.CORS())
	r.Use(middlewares.RequestID())
	r.Use(middlewares.Logger())
	r.Use(gin.Recovery())
	// r.Use(middlewares.RateLimiter()) // Uncomment if rate limiter implemented

	// Initialize handlers
	h := handlers.New(db, cfg)

	// Create auth middleware instance
	authMiddleware := middlewares.NewAuthMiddleware(db)

	// Setup routes with auth middleware
	routes.Setup(r, h, authMiddleware)

	// Add cleanup endpoint for admin use
	r.GET("/api/v1/admin/cleanup/stats", authMiddleware.RequireAuth(), func(c *gin.Context) {
		stats, err := cleanupService.GetCleanupStats()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get cleanup stats"})
			return
		}
		c.JSON(http.StatusOK, stats)
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start cleanup service
	cleanupService.Start()
	log.Printf("Cleanup service started with interval: %v", cfg.TokenCleanupInterval)

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Server shutting down...")

	// Stop cleanup service
	cleanupService.Stop()

	// Give the server 30 seconds to finish handling requests
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}
