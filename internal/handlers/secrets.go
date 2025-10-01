package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CreateSecret handles creating a new secret (if needed separately)
func (h *Handlers) CreateSecret(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "CreateSecret endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// UpdateSecret handles updating an existing secret
func (h *Handlers) UpdateSecret(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "UpdateSecret endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}
