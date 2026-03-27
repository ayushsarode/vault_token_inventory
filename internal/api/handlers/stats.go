package handlers

import (
	"net/http"

	"github.com/ayushsarodey/vault_token_inventory/internal/repository"
	"github.com/gin-gonic/gin"
)

type StatsHandler struct {
	secretRepo *repository.SecretRepo
}

func NewStatsHandler(repo *repository.SecretRepo) *StatsHandler {
	return &StatsHandler{secretRepo: repo}
}

func (h *StatsHandler) GetStats(c *gin.Context) {
	stats, err := h.secretRepo.GetStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch stats"})
		return
	}

	if stats.ByType == nil {
		stats.ByType = make(map[string]int)
	}

	c.JSON(http.StatusOK, stats)
}
