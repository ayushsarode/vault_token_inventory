CREATE TABLE IF NOT EXISTS sync_logs (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id      UUID        NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    sync_type        TEXT        NOT NULL DEFAULT 'full',     
    status           TEXT        NOT NULL DEFAULT 'running', 
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at      TIMESTAMPTZ,
    duration_ms      BIGINT,
    secrets_found    INT         NOT NULL DEFAULT 0,
    secrets_created  INT         NOT NULL DEFAULT 0,
    secrets_updated  INT         NOT NULL DEFAULT 0,
    secrets_deleted  INT         NOT NULL DEFAULT 0,
    error            TEXT
);

CREATE INDEX IF NOT EXISTS idx_sync_logs_provider_id ON sync_logs(provider_id);
CREATE INDEX IF NOT EXISTS idx_sync_logs_started_at  ON sync_logs(started_at DESC);
