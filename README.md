# Vault Token Ingestion & Unified Inventory System

This assignment is a robust, production-grade service designed to ingest secrets and tokens from HashiCorp Vault into a unified, centralized inventory system (PostgreSQL). It ensures idempotency through accurate change detection, features a polling engine, and provides a secure API layer.

## Setup Instructions

### Technology Stack
- **Language**: Go 1.25
- **Database**: PostgreSQL
- **Containerization**: Docker & Docker Compose
- **Deployment**: GCP Compute Engine

### Running the Application

```bash
make build
make run
```

### Seeding Vault with Real Secrets

Once the stack is running, populate the Vault instance with real secrets. The Docker Compose stack runs a full HashiCorp Vault server — all data written to it is stored and served through real Vault APIs:

```bash

# Create secrets with nested paths
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root sg_vault vault kv put secret/app/database host=db.prod.internal port=5432 username=admin password=s3cret
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root sg_vault vault kv put secret/app/api-keys stripe=sk_live_xxx sendgrid=SG.xxx
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root sg_vault vault kv put secret/infra/tls/cert cert="-----BEGIN CERTIFICATE-----" key="-----BEGIN PRIVATE KEY-----"
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root sg_vault vault kv put secret/infra/ssh-keys deploy="ssh-rsa AAAA..."
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root sg_vault vault kv put secret/services/redis host=redis.internal password=r3dis

# Create a token with a short TTL
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root sg_vault vault token create -ttl=30s -display-name="short-lived-svc" -policy=default

# Create a token with no TTL (high-risk — will be flagged)
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root sg_vault vault token create -display-name="no-expiry-admin" -policy=default -no-default-policy
```

### API Endpoints

All protected endpoints require the `X-API-Key` header. The default dev key is `vault_token_inventory-dev-key`.

```bash
API_KEY="vault_token_inventory-dev-key"
BASE="http://localhost:8080"
LIVE_BASE="http://34.135.5.248:8080"
```

**Health Check (public):**
```bash
curl $BASE/health
```

**Trigger a Sync:**
```bash
curl -X POST $BASE/api/v1/sync -H "X-API-Key: $API_KEY"
```

**View Sync Logs:**
```bash
curl $BASE/api/v1/sync/logs -H "X-API-Key: $API_KEY"
```

**List Inventory (with pagination & filters):**
```bash
# Basic list
curl "$BASE/api/v1/inventory" -H "X-API-Key: $API_KEY"

# With filters
curl "$BASE/api/v1/inventory?status=active&path=secret/app&page=1&page_size=10" -H "X-API-Key: $API_KEY"
```

**Get Secret Detail by ID:**
```bash
curl $BASE/api/v1/inventory/<secret-id> -H "X-API-Key: $API_KEY"
```

**Get Version History:**
```bash
curl $BASE/api/v1/inventory/<secret-id>/versions -H "X-API-Key: $API_KEY"
```

**Stats Dashboard:**
```bash
curl $BASE/api/v1/stats -H "X-API-Key: $API_KEY"
```

## Architecture Decisions

The architecture follows Domain-Driven Design principles organized into modular packages, promoting separation of concerns and testability.

1. **Modular Go Layout**: 
   - `cmd/server/`: Contains the application entry point and dependency wiring.
   - `internal/api/`: REST API layer built with the `Gin` framework containing handlers and routing logic.
   - `internal/ingestion/`: The core engine responsible for polling Vault, tracking state, and batch-processing records.
   - `internal/repository/`: The data access layer. Uses raw SQL via `pgx` and `go-sqlbuilder` for predictable, performant queries and transaction management over heavy ORMs.
   - `internal/provider/`: Abstraction over HashiCorp Vault's official SDK, supporting token-based authentication and automatic token renewal.
   - `internal/logger/`: Custom structured logging built on `zerolog` for high-performance and machine-readable output.

2. **Idempotency & Change Detection**: 
   The ingest engine deeply inspects Vault metadata and payload signatures/hashes to determine if a secret actually mutated, rather than just upserting blindly. This preserves database integrity and reduces unnecessary write operations.

3. **Resiliency with Go-Backoff**:
   Network instability and Vault downtime are handled gracefully. The `cenkalti/backoff` library is used to perform exponential backoffs automatically for critical provider and database operations.

## Tradeoffs

1. **Raw SQL (`pgx`) vs. ORM**:
   - *Decision:* Opted for `pgx` and `go-sqlbuilder` directly.
   - *Tradeoff:* Requires more boilerplate to map rows to Go structs manually compared to an ORM like GORM. However, it ensures full control over query performance, connection pooling, and strict idempotency handling when creating upsert constraints.

2. **Gin vs Standard Library `net/http`**:
   - *Decision:* The `gin-gonic/gin` framework was chosen for the API.
   - *Tradeoff:* While the standard library in Go 1.25+ has better routing, Gin provides a highly optimized routing tree out of the box with extensive, battle-tested middleware for recovery, logging, and validation, accelerating the development of the webhook/API layer.

