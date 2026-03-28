package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type Provider struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Config    []byte    `json:"config"`
	CreatedAt time.Time `json:"created_at"`
}

type Secret struct {
	ID           uuid.UUID  `json:"id"`
	ProviderID   uuid.UUID  `json:"provider_id"`
	Path         string     `json:"path"`
	Key          string     `json:"key"`
	SecretType   string     `json:"secret_type"`
	Status       string     `json:"status"`
	TTL          *int64     `json:"ttl,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Policies     []string   `json:"policies"`
	Owner        string     `json:"owner"`
	LastSyncedAt time.Time  `json:"last_synced_at"`
	RiskScore    int        `json:"risk_score"`
	Metadata     json.RawMessage `json:"metadata"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type SecretVersion struct {
	ID          uuid.UUID `json:"id"`
	SecretID    uuid.UUID `json:"secret_id"`
	Version     int       `json:"version"`
	CreatedTime time.Time `json:"created_time"`
	Metadata    json.RawMessage `json:"metadata"`
}

type SyncLog struct {
	ID             uuid.UUID  `json:"id"`
	ProviderID     uuid.UUID  `json:"provider_id"`
	SyncType       string     `json:"sync_type"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	DurationMs     *int64     `json:"duration_ms,omitempty"`
	SecretsFound   int        `json:"secrets_found"`
	SecretsCreated int        `json:"secrets_created"`
	SecretsUpdated int        `json:"secrets_updated"`
	SecretsDeleted int        `json:"secrets_deleted"`
	Error          *string    `json:"error,omitempty"`
}

type StatsResponse struct {
	TotalSecrets int            `json:"total_secrets"`
	ByStatus     map[string]int `json:"by_status"`
	ByType       map[string]int `json:"by_type"`
	ExpiringSoon int            `json:"expiring_soon"`
	Expired      int            `json:"expired"`
	HighRisk     int            `json:"high_risk"` 
	LastSyncAt   *time.Time     `json:"last_sync_at"`
}

type ListFilter struct {
	ProviderID *uuid.UUID
	Status     string
	SecretType string
	Path       string
	Search     string
	Page       int
	Limit      int
}
