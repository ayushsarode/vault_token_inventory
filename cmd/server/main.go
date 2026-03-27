package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ayushsarodey/vault_token_inventory/internal/api"
	"github.com/ayushsarodey/vault_token_inventory/internal/config"
	"github.com/ayushsarodey/vault_token_inventory/internal/ingestion"
	"github.com/ayushsarodey/vault_token_inventory/internal/logger"
	zlog "github.com/rs/zerolog/log"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to load config")
	}

	zlog.Logger = logger.NewLogger(cfg.Server.ProductionMode)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := initDatabase(ctx, cfg)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Database setup failed")
	}
	defer pool.Close()

	r := initRepos(pool)

	vaultClient, err := initVault(cfg)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Vault client connection failed")
	}

	engine := ingestion.NewEngine(r.provider, r.secret, r.syncLog, vaultClient, cfg.Ingestion.IntervalSeconds)
	engine.Start(ctx, cfg.Ingestion.FullSyncOnStart)

	router := api.NewRouter(pool, r.secret, r.syncLog, engine, cfg.Server.APIKey)
	serverAddr := fmt.Sprintf(":%d", cfg.Server.Port)
	zlog.Info().Str("addr", serverAddr).Msg("HTTP server listening")

	go func() {
		if err := router.Run(serverAddr); err != nil {
			zlog.Fatal().Err(err).Msg("HTTP server crashed")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	zlog.Info().Msg("Shutting down service...")
	cancel()
	pool.Close()
	zlog.Info().Msg("Shutdown complete")
}
