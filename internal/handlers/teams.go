package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CreateTeam creates a new team for a project
func (h *Handlers) CreateTeam(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "CreateTeam endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// AddTeamMember adds a user to a team
func (h *Handlers) AddTeamMember(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "AddTeamMember endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// GrantScopeAccess grants access to a scope for a team or user
func (h *Handlers) GrantScopeAccess(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "GrantScopeAccess endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// RevokeScopeAccess revokes access to a scope
func (h *Handlers) RevokeScopeAccess(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "RevokeScopeAccess endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// GetScopeAccess returns all access permissions for a scope
func (h *Handlers) GetScopeAccess(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "GetScopeAccess endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}
