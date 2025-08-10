package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CreateScope handles `shush scope <scope-name>`
func (h *Handlers) CreateScope(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "CreateScope endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// DeleteScope handles `shush scope --delete <scope-name>`
func (h *Handlers) DeleteScope(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "DeleteScope endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// GetProjectScopes returns all scopes for a project
func (h *Handlers) GetProjectScopes(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "GetProjectScopes endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// AddSecret handles `shush add <secret-file>`
func (h *Handlers) AddSecret(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "AddSecret endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// RemoveSecret handles `shush rm <secret-file>`
func (h *Handlers) RemoveSecret(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "RemoveSecret endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// GetScopeSecrets returns all secrets for a scope (moved from duplicate)
func (h *Handlers) GetScopeSecrets(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "GetScopeSecrets endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}
