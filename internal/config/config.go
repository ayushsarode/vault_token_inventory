package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Vault     VaultConfig     `mapstructure:"vault"`
	Ingestion IngestionConfig `mapstructure:"ingestion"`
}

type ServerConfig struct {
	Port           int    `mapstructure:"port"`
	ProductionMode bool   `mapstructure:"production_mode"`
	APIKey         string `mapstructure:"api_key"` //nolint:gosec
}

type DatabaseConfig struct {
	DSN string `mapstructure:"dsn"`
}

type VaultConfig struct {
	Address  string `mapstructure:"address"`
	Token    string `mapstructure:"token"`
	RoleID   string `mapstructure:"role_id"`
	SecretID string `mapstructure:"secret_id"`
	Mount    string `mapstructure:"mount"`
}

type IngestionConfig struct {
	IntervalSeconds  int  `mapstructure:"interval_seconds"`
	FullSyncOnStart  bool `mapstructure:"full_sync_on_start"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/app")
	viper.AutomaticEnv()

	// Env overrides
	_ = viper.BindEnv("server.api_key", "API_KEY")
	_ = viper.BindEnv("database.dsn", "DATABASE_DSN")
	_ = viper.BindEnv("vault.address", "VAULT_ADDR")
	_ = viper.BindEnv("vault.token", "VAULT_TOKEN")
	_ = viper.BindEnv("vault.role_id", "VAULT_ROLE_ID")
	_ = viper.BindEnv("vault.secret_id", "VAULT_SECRET_ID")
	_ = viper.BindEnv("vault.mount", "VAULT_MOUNT")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	return &cfg, nil
}
