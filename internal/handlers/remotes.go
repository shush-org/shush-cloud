package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AddRemote handles `shush remote add <name> <url>`
func (h *Handlers) AddRemote(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "AddRemote endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// RemoveRemote handles `shush remote rm <remote-scope-name>`
func (h *Handlers) RemoveRemote(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "RemoveRemote endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// GetProjectRemotes returns all remotes for a project
func (h *Handlers) GetProjectRemotes(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "GetProjectRemotes endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}
