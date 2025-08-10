package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) CreateProject(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "CreateProject endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

func (h *Handlers) GetProject(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "GetProject endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

func (h *Handlers) GetUserProjects(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "GetUserProjects endpoint is not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}
