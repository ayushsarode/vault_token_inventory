package repository

import (
	"context"

	"github.com/ayushsarodey/vault_token_inventory/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SyncLogRepo struct {
	pool *pgxpool.Pool
}

func NewSyncLogRepo(pool *pgxpool.Pool) *SyncLogRepo {
	return &SyncLogRepo{pool: pool}
}

func (r *SyncLogRepo) CreateSyncLog(ctx context.Context, log *models.SyncLog) error {
	query := `
		INSERT INTO sync_logs (provider_id, sync_type, status, started_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`
	err := r.pool.QueryRow(ctx, query, log.ProviderID, log.SyncType, log.Status, log.StartedAt).Scan(&log.ID)
	return err
}

func (r *SyncLogRepo) UpdateSyncLog(ctx context.Context, log *models.SyncLog) error {
	query := `
		UPDATE sync_logs
		SET status = $1, finished_at = $2, duration_ms = $3,
			secrets_found = $4, secrets_created = $5, secrets_updated = $6,
			secrets_deleted = $7, error = $8
		WHERE id = $9
	`
	_, err := r.pool.Exec(ctx, query,
		log.Status, log.FinishedAt, log.DurationMs,
		log.SecretsFound, log.SecretsCreated, log.SecretsUpdated,
		log.SecretsDeleted, log.Error, log.ID)
	return err
}

func (r *SyncLogRepo) ListSyncLogs(ctx context.Context) ([]models.SyncLog, error) {
	query := `
		SELECT id, provider_id, sync_type, status, started_at, finished_at, duration_ms, 
			   secrets_found, secrets_created, secrets_updated, secrets_deleted, error
		FROM sync_logs
		ORDER BY started_at DESC
		LIMIT 50
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.SyncLog
	for rows.Next() {
		var l models.SyncLog
		err := rows.Scan(
			&l.ID, &l.ProviderID, &l.SyncType, &l.Status, &l.StartedAt, &l.FinishedAt, &l.DurationMs,
			&l.SecretsFound, &l.SecretsCreated, &l.SecretsUpdated, &l.SecretsDeleted, &l.Error,
		)
		if err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}

	return logs, rows.Err()
}
