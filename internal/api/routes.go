package api

import (
	"github.com/ayushsarodey/vault_token_inventory/internal/api/handlers"
	"github.com/ayushsarodey/vault_token_inventory/internal/api/middleware"
	"github.com/ayushsarodey/vault_token_inventory/internal/ingestion"
	"github.com/ayushsarodey/vault_token_inventory/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewRouter(
	pool *pgxpool.Pool,
	secretRepo *repository.SecretRepo,
	syncLogRepo *repository.SyncLogRepo,
	engine *ingestion.Engine,
	apiKey string,
) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	r.Use(middleware.StructuredLogger())
	r.Use(gin.Recovery())

	// Handlers
	healthHandler := handlers.NewHealthHandler(pool)
	syncHandler := handlers.NewSyncHandler(engine, syncLogRepo)
	inventoryHandler := handlers.NewInventoryHandler(secretRepo)
	statsHandler := handlers.NewStatsHandler(secretRepo)

	// Public Routes
	r.GET("/health", healthHandler.Check)

	// Protected Routes
	protected := r.Group("/api/v1")
	protected.Use(middleware.APIKeyAuth(apiKey))
	{
		protected.POST("/sync", syncHandler.TriggerSync)
		protected.GET("/sync/logs", syncHandler.GetLogs)
		
		protected.GET("/inventory", inventoryHandler.List)
		protected.GET("/inventory/:id", inventoryHandler.Get)
		protected.GET("/inventory/:id/versions", inventoryHandler.GetVersions)
		
		protected.GET("/stats", statsHandler.GetStats)
	}

	return r
}
