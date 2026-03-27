CREATE TABLE IF NOT EXISTS secret_versions (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id    UUID        NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version      INT         NOT NULL DEFAULT 1,
    created_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata     JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_secret_id ON secret_versions(secret_id);
