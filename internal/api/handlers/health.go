package handlers

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	pool *pgxpool.Pool
}

func NewHealthHandler(pool *pgxpool.Pool) *HealthHandler {
	return &HealthHandler{pool: pool}
}

func (h *HealthHandler) Check(c *gin.Context) {
	err := h.pool.Ping(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "unhealthy",
			"details": "database uncreachable",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"database": "connected",
	})
}
