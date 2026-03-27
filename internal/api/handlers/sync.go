package handlers

import (
	"context"
	"net/http"

	"github.com/ayushsarodey/vault_token_inventory/internal/ingestion"
	"github.com/ayushsarodey/vault_token_inventory/internal/repository"
	"github.com/gin-gonic/gin"
)

type SyncHandler struct {
	engine *ingestion.Engine
	syncLogRepo *repository.SyncLogRepo
}

func NewSyncHandler(eng *ingestion.Engine, logRepo *repository.SyncLogRepo) *SyncHandler {
	return &SyncHandler{
		engine:      eng,
		syncLogRepo: logRepo,
	}
}

func (h *SyncHandler) TriggerSync(c *gin.Context) {
	go func() {
		_ = h.engine.RunSync(context.Background())
	}()

	c.JSON(http.StatusOK, gin.H{"status": "sync triggered in background"})
}

func (h *SyncHandler) GetLogs(c *gin.Context) {
	logs, err := h.syncLogRepo.ListSyncLogs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sync logs"})
		return
	}
	c.JSON(http.StatusOK, logs)
}
