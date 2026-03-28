package ingestion

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/ayushsarodey/vault_token_inventory/internal/models"
	"github.com/ayushsarodey/vault_token_inventory/internal/provider/hashicorp"
	"github.com/ayushsarodey/vault_token_inventory/internal/repository"
	"github.com/rs/zerolog/log"
)

type Engine struct {
	providerRepo *repository.ProviderRepo
	secretRepo   *repository.SecretRepo
	syncLogRepo  *repository.SyncLogRepo
	vaultClient  *hashicorp.VaultClient
	interval     time.Duration
	syncLock     sync.Mutex
}

func NewEngine(
	pRepo *repository.ProviderRepo,
	sRepo *repository.SecretRepo,
	lRepo *repository.SyncLogRepo,
	vc *hashicorp.VaultClient,
	intervalSec int,
) *Engine {
	return &Engine{
		providerRepo: pRepo,
		secretRepo:   sRepo,
		syncLogRepo:  lRepo,
		vaultClient:  vc,
		interval:     time.Duration(intervalSec) * time.Second,
	}
}

func (e *Engine) Start(ctx context.Context, runOnInit bool) chan struct{} {
	stopCh := make(chan struct{})

	if runOnInit {
		go func() {
			err := e.RunSync(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Initial sync failed")
			}
		}()
	}

	ticker := time.NewTicker(e.interval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-stopCh:
				ticker.Stop()
				return
			case <-ticker.C:
				err := e.RunSync(ctx)
				if err != nil {
					log.Error().Err(err).Msg("Scheduled sync failed")
				}
			}
		}
	}()

	return stopCh
}

//nolint:cyclop,funlen
func (e *Engine) RunSync(ctx context.Context) error {
	// Prevent overlapping syncs
	if !e.syncLock.TryLock() {
		log.Warn().Msg("Sync already in progress, skipping run.")
		return nil
	}
	defer e.syncLock.Unlock()

	startTime := time.Now()

	provider, err := e.providerRepo.GetOrCreateProvider(ctx, "local-vault", "hashicorp_vault", map[string]any{
		"mount": "secret",
	})
	if err != nil {
		return fmt.Errorf("getting provider: %w", err)
	}

	syncLog := &models.SyncLog{
		ProviderID: provider.ID,
		SyncType:   "full",
		Status:     "running",
		StartedAt:  startTime,
	}
	if err := e.syncLogRepo.CreateSyncLog(ctx, syncLog); err != nil {
		return fmt.Errorf("creating sync log: %w", err)
	}

	var errorStr string
	defer func() {
		finishTime := time.Now()
		dur := finishTime.Sub(startTime).Milliseconds()
		syncLog.FinishedAt = &finishTime
		syncLog.DurationMs = &dur
		if errorStr != "" {
			syncLog.Status = "failed"
			syncLog.Error = &errorStr
		} else {
			syncLog.Status = "success"
		}

		_ = e.syncLogRepo.UpdateSyncLog(context.Background(), syncLog) 
	}()

	log.Info().Str("provider", provider.Name).Msg("Starting Vault sync")

	var extracted []hashicorp.ExtractedSecret
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 30 * time.Second //nolint:mnd 

	operation := func() error {
		var fetchErr error
		extracted, fetchErr = e.vaultClient.FetchAll(ctx)
		if fetchErr != nil {
			return fetchErr
		}
		
		tokens, _ := e.vaultClient.FetchTokens(ctx)
		extracted = append(extracted, tokens...)
		return nil
	}

	err = backoff.RetryNotify(operation, backoff.WithContext(bo, ctx), func(err error, d time.Duration) {
		log.Warn().Err(err).Dur("backoff", d).Msg("Vault fetch failed, retrying...")
	})

	if err != nil {
		errorStr = err.Error()
		return fmt.Errorf("fetching vault secrets exhausted retries: %w", err)
	}

	syncLog.SecretsFound = len(extracted)

	
	for _, ext := range extracted {
		risk := 0
		var expiresAt *time.Time
		if ext.TTL == nil || *ext.TTL == 0 {
			risk += 5
		} else {
			ea := time.Now().Add(time.Duration(*ext.TTL) * time.Second)
			expiresAt = &ea
		}
		if ext.Owner == "" {
			risk += 2
		}

		policies := ext.Policies
		if policies == nil {
			policies = []string{}
		}

		dbSecret := &models.Secret{
			ProviderID:   provider.ID,
			Path:         ext.Path,
			Key:          ext.Key,
			SecretType:   ext.SecretType,
			Status:       "active",
			TTL:          ext.TTL,
			ExpiresAt:    expiresAt,
			Policies:     policies,
			Owner:        ext.Owner,
			Metadata:     ext.Metadata,
			LastSyncedAt: time.Now(),
			RiskScore:    risk,
		}

		action, secretID, err := e.secretRepo.UpsertSecret(ctx, dbSecret)
		if err != nil {
			log.Error().Err(err).Str("path", ext.Path).Msg("Failed to upsert secret")
			errorStr = err.Error()
			continue
		}

	
		switch action {
		case "created":
			syncLog.SecretsCreated++
			_ = e.secretRepo.InsertSecretVersion(ctx, secretID, ext.Metadata)
		case "updated":
			syncLog.SecretsUpdated++
			_ = e.secretRepo.InsertSecretVersion(ctx, secretID, ext.Metadata)
		}
	}

	log.Info().
		Int("found", syncLog.SecretsFound).
		Int("created", syncLog.SecretsCreated).
		Int("updated", syncLog.SecretsUpdated).
		Msg("Sync complete")

	return nil
}
