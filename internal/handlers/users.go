package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) CreateUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "CreateUser endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

func (h *Handlers) GetUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "GetUser endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

func (h *Handlers) UpdateUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "UpdateUser endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

func (h *Handlers) DeleteUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "DeleteUser endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}
