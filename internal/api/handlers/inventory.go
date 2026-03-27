package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ayushsarodey/vault_token_inventory/internal/models"
	"github.com/ayushsarodey/vault_token_inventory/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type InventoryHandler struct {
	secretRepo *repository.SecretRepo
}

func NewInventoryHandler(repo *repository.SecretRepo) *InventoryHandler {
	return &InventoryHandler{secretRepo: repo}
}

//nolint:cyclop
func (h *InventoryHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	filter := models.ListFilter{
		Status:     c.Query("status"),
		SecretType: c.Query("type"),
		Path:       c.Query("path"),
		Search:     c.Query("search"),
		Page:       page,
		Limit:      limit,
	}

	if providerIDStr := c.Query("provider_id"); providerIDStr != "" {
		if u, err := uuid.Parse(providerIDStr); err == nil {
			filter.ProviderID = &u
		}
	}

	secrets, total, err := h.secretRepo.ListSecrets(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch inventory", "details": err.Error()})
		return
	}

	if secrets == nil {
		secrets = []models.Secret{}
	}

	for i := range secrets {
		if secrets[i].ExpiresAt != nil {
			t := secrets[i].ExpiresAt.UTC()
			secrets[i].ExpiresAt = &t
			if t.Before(time.Now().UTC()) {
				secrets[i].Status = "expired"
			}
		}
		secrets[i].LastSyncedAt = secrets[i].LastSyncedAt.UTC()
		secrets[i].CreatedAt = secrets[i].CreatedAt.UTC()
		secrets[i].UpdatedAt = secrets[i].UpdatedAt.UTC()
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  secrets,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *InventoryHandler) Get(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing ID parameter"})
		return
	}

	secret, err := h.secretRepo.GetSecretByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found or invalid UUID format"})
		return
	}

	if secret.ExpiresAt != nil {
		t := secret.ExpiresAt.UTC()
		secret.ExpiresAt = &t
		if t.Before(time.Now().UTC()) {
			secret.Status = "expired"
		}
	}
	secret.LastSyncedAt = secret.LastSyncedAt.UTC()
	secret.CreatedAt = secret.CreatedAt.UTC()
	secret.UpdatedAt = secret.UpdatedAt.UTC()

	c.JSON(http.StatusOK, secret)
}

func (h *InventoryHandler) GetVersions(c *gin.Context) {
	id := c.Param("id")

	versions, err := h.secretRepo.ListSecretVersions(c.Request.Context(), id)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch versions")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query list"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret_id": id,
		"versions":  versions,
	})
}
