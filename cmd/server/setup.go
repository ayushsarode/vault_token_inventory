package main

import (
	"context"

	"github.com/ayushsarodey/vault_token_inventory/internal/config"
	"github.com/ayushsarodey/vault_token_inventory/internal/database"
	"github.com/ayushsarodey/vault_token_inventory/internal/migrations"
	"github.com/ayushsarodey/vault_token_inventory/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	zlog "github.com/rs/zerolog/log"
)

type repos struct {
	provider *repository.ProviderRepo
	secret   *repository.SecretRepo
	syncLog  *repository.SyncLogRepo
}

func initDatabase(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	pool, err := database.NewPool(ctx, cfg.Database.DSN)
	if err != nil {
		return nil, err
	}

	if err := migrations.Run(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	zlog.Info().Msg("Database connected & migrated")

	return pool, nil
}

func initRepos(pool *pgxpool.Pool) repos {
	return repos{
		provider: repository.NewProviderRepo(pool),
		secret:   repository.NewSecretRepo(pool),
		syncLog:  repository.NewSyncLogRepo(pool),
	}
}
