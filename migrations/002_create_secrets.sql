CREATE TABLE IF NOT EXISTS secrets (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id    UUID        NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    path           TEXT        NOT NULL,
    key            TEXT        NOT NULL,
    secret_type    TEXT        NOT NULL DEFAULT 'generic',
    status         TEXT        NOT NULL DEFAULT 'active',
    ttl            BIGINT,                  -- seconds, NULL = no TTL
    expires_at     TIMESTAMPTZ,
    policies       TEXT[]      NOT NULL DEFAULT '{}',
    owner          TEXT        NOT NULL DEFAULT '',
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    risk_score     INT         NOT NULL DEFAULT 0,
    metadata       JSONB       NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider_id, path, key)
);

CREATE INDEX IF NOT EXISTS idx_secrets_provider_id ON secrets(provider_id);
CREATE INDEX IF NOT EXISTS idx_secrets_status       ON secrets(status);
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at   ON secrets(expires_at);
CREATE INDEX IF NOT EXISTS idx_secrets_risk_score   ON secrets(risk_score DESC);
