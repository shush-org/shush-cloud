package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CommitSecrets handles `shush commit [-m <commit-message>]`
func (h *Handlers) CommitSecrets(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "CommitSecrets endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// GetScopeCommits returns commits for a scope (for pull operations)
func (h *Handlers) GetScopeCommits(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "GetScopeCommits endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// PushScope handles `shush push [-u <remote-scope-name>]`
func (h *Handlers) PushScope(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "PushScope endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// PullScope handles `shush pull [-u <remote-scope-name>]`
func (h *Handlers) PullScope(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "PullScope endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}
