package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/shush-org/shush-cloud/internal/handlers"
	"github.com/shush-org/shush-cloud/internal/middlewares"
)

func Setup(r *gin.Engine, h *handlers.Handlers, auth *middlewares.AuthMiddleware) {
	api := r.Group("/api/v1")

	// Health check
	api.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Authentication routes (for CLI) - No auth required
	authRoutes := api.Group("/auth")
	{
		authRoutes.POST("/device/login", h.DeviceLogin)                       // shush login
		authRoutes.POST("/device/logout", auth.RequireAuth(), h.DeviceLogout) // shush logout
		authRoutes.GET("/devices", auth.RequireAuth(), h.ListUserDevices)     // list/manage devices
	}

	// User routes - Most require auth
	users := api.Group("/users")
	{
		users.POST("", h.CreateUser) // Might be used during registration
		users.GET("/:id", auth.RequireAuth(), h.GetUser)
		users.PUT("/:id", auth.RequireAuth(), h.UpdateUser)
		users.DELETE("/:id", auth.RequireAuth(), h.DeleteUser)
		users.GET("/:id/projects", auth.RequireAuth(), h.GetUserProjects)
	}

	// Project routes - All require auth
	projects := api.Group("/projects", auth.RequireAuth())
	{
		projects.POST("", h.CreateProject) // shush init
		projects.GET("/:projectId", h.GetProject)
		projects.GET("/:projectId/scopes", h.GetProjectScopes)
		projects.GET("/:projectId/remotes", h.GetProjectRemotes)
		projects.POST("/:projectId/remotes", h.AddRemote)
		projects.DELETE("/:projectId/remotes/:remoteName", h.RemoveRemote)
	}

	// Scope routes - All require auth
	scopes := api.Group("/scopes", auth.RequireAuth())
	{
		scopes.POST("", h.CreateScope)                          // shush scope <name>
		scopes.DELETE("/:id", h.DeleteScope)                    // shush scope --delete <name>
		scopes.GET("/:scopeId/secrets", h.GetScopeSecrets)      // list secrets in scope
		scopes.POST("/:scopeId/secrets", h.AddSecret)           // shush add <secret-file>
		scopes.GET("/:scopeId/commits", h.GetScopeCommits)      // shush pull (get commits)
		scopes.POST("/:scopeId/commits", h.CommitSecrets)       // shush commit
		scopes.GET("/:scopeId/access", h.GetScopeAccess)        // list access permissions
		scopes.POST("/:scopeId/access", h.GrantScopeAccess)     // grant access
		scopes.DELETE("/access/:accessId", h.RevokeScopeAccess) // revoke access
	}

	// Secret routes - All require auth
	secrets := api.Group("/secrets", auth.RequireAuth())
	{
		secrets.DELETE("/:id", h.RemoveSecret) // shush rm <secret-file>
		secrets.POST("", h.CreateSecret)       // create individual secret
		secrets.PUT("/:id", h.UpdateSecret)    // update individual secret
	}

	// Team routes - All require auth
	teams := api.Group("/teams", auth.RequireAuth())
	{
		teams.POST("", h.CreateTeam)            // create team
		teams.POST("/members", h.AddTeamMember) // add team member
	}

	// Git-like operations - All require auth
	git := api.Group("/git", auth.RequireAuth())
	{
		git.POST("/push", h.PushScope) // shush push
		git.POST("/pull", h.PullScope) // shush pull
	}
}
