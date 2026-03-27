package repository

import (
	"context"
	"errors"
	"time"

	"github.com/ayushsarodey/vault_token_inventory/internal/models"
	"github.com/huandu/go-sqlbuilder"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SecretRepo struct {
	pool *pgxpool.Pool
}

func NewSecretRepo(pool *pgxpool.Pool) *SecretRepo {
	return &SecretRepo{pool: pool}
}

func (r *SecretRepo) UpsertSecret(ctx context.Context, s *models.Secret) (string, string, error) {
	query := `
		INSERT INTO secrets (provider_id, path, key, secret_type, status, ttl, expires_at, policies, owner, last_synced_at, risk_score, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (provider_id, path, key) 
		DO UPDATE SET
			secret_type = EXCLUDED.secret_type,
			status = EXCLUDED.status,
			ttl = EXCLUDED.ttl,
			expires_at = EXCLUDED.expires_at,
			policies = EXCLUDED.policies,
			owner = EXCLUDED.owner,
			last_synced_at = EXCLUDED.last_synced_at,
			risk_score = EXCLUDED.risk_score,
			metadata = EXCLUDED.metadata,
			updated_at = NOW()
		WHERE secrets.metadata IS DISTINCT FROM EXCLUDED.metadata
		   OR secrets.ttl IS DISTINCT FROM EXCLUDED.ttl
		   OR secrets.owner IS DISTINCT FROM EXCLUDED.owner
		   OR secrets.policies IS DISTINCT FROM EXCLUDED.policies
		RETURNING (xmax = 0) AS inserted, id
	`

	var inserted bool
	var returnedID string
	err := r.pool.QueryRow(ctx, query,
		s.ProviderID, s.Path, s.Key, s.SecretType, s.Status,
		s.TTL, s.ExpiresAt, s.Policies, s.Owner, s.LastSyncedAt,
		s.RiskScore, s.Metadata,
	).Scan(&inserted, &returnedID)

	if errors.Is(err, pgx.ErrNoRows) {
		// Update lock skipped, so this acts as unchanged
		return "unchanged", "", nil
	} else if err != nil {
		return "", "", err
	}

	if inserted {
		return "created", returnedID, nil
	}
	return "updated", returnedID, nil
}

func (r *SecretRepo) InsertSecretVersion(ctx context.Context, secretID string, metadata []byte) error {
	query := `
		INSERT INTO secret_versions (secret_id, metadata, version)
		VALUES ($1, $2, (SELECT COALESCE(MAX(version), 0) + 1 FROM secret_versions WHERE secret_id = $1))
	`
	_, err := r.pool.Exec(ctx, query, secretID, string(metadata))
	return err
}

func (r *SecretRepo) ListSecretVersions(ctx context.Context, secretID string) ([]map[string]any, error) {
	query := `
		SELECT version, created_time, metadata 
		FROM secret_versions 
		WHERE secret_id = $1 
		ORDER BY version DESC
	`

	rows, err := r.pool.Query(ctx, query, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []map[string]any
	for rows.Next() {
		var (
			version int
			created time.Time
			meta    []byte
		)
		if err := rows.Scan(&version, &created, &meta); err != nil {
			return nil, err
		}
		versions = append(versions, map[string]any{
			"version":      version,
			"created_time": created,
			"metadata":     string(meta),
		})
	}
	return versions, rows.Err()
}

//nolint:funlen
func (r *SecretRepo) ListSecrets(ctx context.Context, f models.ListFilter) ([]models.Secret, int, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	countSb := sqlbuilder.PostgreSQL.NewSelectBuilder()

	sb.Select("id", "provider_id", "path", "key", "secret_type", "status", "ttl", "expires_at", "policies", "owner", "last_synced_at", "risk_score", "metadata", "created_at", "updated_at")
	sb.From("secrets")

	countSb.Select("COUNT(*)")
	countSb.From("secrets")

	if f.ProviderID != nil {
		sb.Where(sb.Equal("provider_id", *f.ProviderID))
		countSb.Where(countSb.Equal("provider_id", *f.ProviderID))
	}
	if f.Status != "" {
		sb.Where(sb.Equal("status", f.Status))
		countSb.Where(countSb.Equal("status", f.Status))
	}
	if f.SecretType != "" {
		sb.Where(sb.Equal("secret_type", f.SecretType))
		countSb.Where(countSb.Equal("secret_type", f.SecretType))
	}
	if f.Path != "" {
		pathPrefix := f.Path + "%"
		sb.Where("path LIKE " + sb.Var(pathPrefix))
		countSb.Where("path LIKE " + countSb.Var(pathPrefix))
	}
	if f.Search != "" {
		search := "%" + f.Search + "%"
		sb.Where(sb.Or(
			"path ILIKE "+sb.Var(search),
			"key ILIKE "+sb.Var(search),
		))
		countSb.Where(countSb.Or(
			"path ILIKE "+countSb.Var(search),
			"key ILIKE "+countSb.Var(search),
		))
	}

	countQuery, countArgs := countSb.Build()
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sb.OrderBy("path ASC", "key ASC")
	sb.Limit(f.Limit)
	sb.Offset((f.Page - 1) * f.Limit)

	query, args := sb.Build()
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var secrets []models.Secret
	for rows.Next() {
		var s models.Secret
		if err := rows.Scan(
			&s.ID, &s.ProviderID, &s.Path, &s.Key, &s.SecretType, &s.Status,
			&s.TTL, &s.ExpiresAt, &s.Policies, &s.Owner, &s.LastSyncedAt,
			&s.RiskScore, &s.Metadata, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		secrets = append(secrets, s)
	}

	return secrets, total, nil
}

func (r *SecretRepo) GetSecretByID(ctx context.Context, id string) (*models.Secret, error) {
	query := `
		SELECT id, provider_id, path, key, secret_type, status, ttl, expires_at, policies, owner, last_synced_at, risk_score, metadata, created_at, updated_at
		FROM secrets
		WHERE id = $1
	`
	var s models.Secret
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&s.ID, &s.ProviderID, &s.Path, &s.Key, &s.SecretType, &s.Status,
		&s.TTL, &s.ExpiresAt, &s.Policies, &s.Owner, &s.LastSyncedAt,
		&s.RiskScore, &s.Metadata, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SecretRepo) GetStats(ctx context.Context) (*models.StatsResponse, error) {
	var total, expiringSoon, expired, highRisk int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM secrets`).Scan(&total)
	if err != nil {
		return nil, err
	}

	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM secrets WHERE expires_at < NOW() + INTERVAL '7 days' AND expires_at > NOW()`).Scan(&expiringSoon)
	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM secrets WHERE status = 'expired' OR expires_at < NOW()`).Scan(&expired)
	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM secrets WHERE risk_score >= 7`).Scan(&highRisk)

	byStatus := make(map[string]int)
	rows1, err := r.pool.Query(ctx, `SELECT status, COUNT(*) FROM secrets GROUP BY status`)
	if err == nil {
		for rows1.Next() {
			var st string
			var ct int
			_ = rows1.Scan(&st, &ct)
			byStatus[st] = ct
		}
		rows1.Close()
	}

	byType := make(map[string]int)
	rows2, err := r.pool.Query(ctx, `SELECT secret_type, COUNT(*) FROM secrets GROUP BY secret_type`)
	if err == nil {
		for rows2.Next() {
			var ty string
			var ct int
			_ = rows2.Scan(&ty, &ct)
			byType[ty] = ct
		}
		rows2.Close()
	}

	return &models.StatsResponse{
		TotalSecrets: total,
		ByStatus:     byStatus,
		ByType:       byType,
		ExpiringSoon: expiringSoon,
		Expired:      expired,
		HighRisk:     highRisk,
	}, nil
}
