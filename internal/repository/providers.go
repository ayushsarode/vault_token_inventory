package repository

import (
	"context"
	"encoding/json"

	"github.com/ayushsarodey/vault_token_inventory/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProviderRepo struct {
	pool *pgxpool.Pool
}

func NewProviderRepo(pool *pgxpool.Pool) *ProviderRepo {
	return &ProviderRepo{pool: pool}
}

func (r *ProviderRepo) GetOrCreateProvider(ctx context.Context, name, pType string, config map[string]any) (*models.Provider, error) {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	query := `
		INSERT INTO providers (name, type, config)
		VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET config = EXCLUDED.config
		RETURNING id, name, type, config, created_at
	`

	var p models.Provider
	err = r.pool.QueryRow(ctx, query, name, pType, configJSON).Scan(
		&p.ID, &p.Name, &p.Type, &p.Config, &p.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &p, nil
}
