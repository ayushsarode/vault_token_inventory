package main

import (
	"github.com/ayushsarodey/vault_token_inventory/internal/config"
	"github.com/ayushsarodey/vault_token_inventory/internal/provider/hashicorp"
	zlog "github.com/rs/zerolog/log"
)

func initVault(cfg *config.Config) (*hashicorp.VaultClient, error) {
	client, err := hashicorp.NewVaultClient(
		cfg.Vault.Address,
		cfg.Vault.Token,
		cfg.Vault.RoleID,
		cfg.Vault.SecretID,
		cfg.Vault.Mount,
	)
	if err != nil {
		return nil, err
	}

	zlog.Info().Str("addr", cfg.Vault.Address).Msg("Vault client initialized")

	return client, nil
}
