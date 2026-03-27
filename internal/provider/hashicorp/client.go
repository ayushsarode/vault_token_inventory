package hashicorp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
)

type VaultClient struct {
	client *api.Client
	mount  string
}

type ExtractedSecret struct {
	Path       string
	Key        string
	SecretType string
	TTL        *int64
	Policies   []string
	Owner      string
	Metadata   []byte
}

func NewVaultClient(addr, token, roleID, secretID, mount string) (*VaultClient, error) {
	config := api.DefaultConfig()
	config.Address = addr

	config.MaxRetries = 5
	config.Timeout = 30 * time.Second //nolint:mnd

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	//nolint:gocritic,nestif
	if token != "" {
		client.SetToken(token)
		// Check if token is valid
		_, err = client.Auth().Token().LookupSelf()
		if err != nil {
			return nil, fmt.Errorf("invalid token: %w", err)
		}
	} else if roleID != "" && secretID != "" {
		secret, err := client.Logical().Write("auth/approle/login", map[string]any{
			"role_id":   roleID,
			"secret_id": secretID,
		})
		if err != nil {
			return nil, fmt.Errorf("approle login failed: %w", err)
		}
		if secret == nil || secret.Auth == nil {
			return nil, errors.New("approle login returned no auth info")
		}
		client.SetToken(secret.Auth.ClientToken)
	} else {
		return nil, errors.New("no valid credentials provided (need token or approle)")
	}

	return &VaultClient{
		client: client,
		mount:  mount,
	}, nil
}

//nolint:nestif
func (c *VaultClient) FetchAll(ctx context.Context) ([]ExtractedSecret, error) {
	isV2 := true

	mounts, err := c.client.Sys().ListMounts()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to check sys/mounts permissions (defaulting to KV v2)")
	} else {
		mountPath := c.mount
		if mountPath != "" && mountPath[len(mountPath)-1] != '/' {
			mountPath += "/"
		}
		
		if mountInfo, ok := mounts[mountPath]; ok {
			if version, exists := mountInfo.Options["version"]; exists && version == "1" {
				isV2 = false
				log.Info().Str("mount", c.mount).Msg("Dynamic detection: KV Type Version 1")
			} else {
				log.Info().Str("mount", c.mount).Msg("Dynamic detection: KV Type Version 2")
			}
		} else {
			log.Warn().Str("mount", mountPath).Msg("Mount path not found in sys/mounts (defaulting to KV v2)")
		}
	}

	var allSecrets []ExtractedSecret

	basePath := c.mount
	if isV2 {
		basePath = c.mount + "/metadata"
	}

	// Start recursive walk
	err = c.walk(ctx, basePath, isV2, &allSecrets)
	return allSecrets, err
}

//nolint:cyclop
func (c *VaultClient) FetchTokens(ctx context.Context) ([]ExtractedSecret, error) {
	var results []ExtractedSecret

	secret, err := c.client.Logical().ListWithContext(ctx, "auth/token/accessors")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list token accessors (requires sudo/root)")
		return results, nil // Graceful failure if no permission
	}
	if secret == nil || len(secret.Data) == 0 {
		return results, nil
	}

	keys, ok := secret.Data["keys"].([]any)
	if !ok {
		return results, nil
	}

	for _, k := range keys {
		accessor, ok := k.(string)
		if !ok {
			continue
		}

		s, err := c.client.Logical().WriteWithContext(ctx, "auth/token/lookup-accessor", map[string]any{
			"accessor": accessor,
		})
		if err != nil || s == nil || s.Data == nil {
			log.Warn().Str("accessor", accessor).Msg("Failed to lookup token accessor")
			continue
		}

		var ttlPtr *int64
		if ttlVal, ok := s.Data["ttl"]; ok {
			switch v := ttlVal.(type) {
			case float64:
				ttl := int64(v)
				ttlPtr = &ttl
			case json.Number:
				if ttl, err := v.Int64(); err == nil && ttl > 0 {
					ttlPtr = &ttl
				}
			case string:
				if ttl, err := strconv.ParseInt(v, 10, 64); err == nil && ttl > 0 {
					ttlPtr = &ttl
				}
			}
		}

		valBytes, _ := json.Marshal(s.Data)

		ext := ExtractedSecret{
			Path:       "auth/token/accessors",
			Key:        accessor,
			SecretType: "vault_token",
			Metadata:   valBytes,
			TTL:        ttlPtr,
		}

		results = append(results, ext)
	}

	return results, nil
}

//nolint:gocognit,funlen,cyclop,nestif,unparam
func (c *VaultClient) walk(ctx context.Context, currentPath string, isV2 bool, results *[]ExtractedSecret) error {
	log.Debug().Str("path", currentPath).Msg("Walking Vault path")

	secret, err := c.client.Logical().ListWithContext(ctx, currentPath)
	if err != nil {
		log.Warn().Err(err).Str("path", currentPath).Msg("Failed to list path (permission denied?)")
		return nil // skip on error (graceful partial failure)
	}
	if secret == nil || secret.Data == nil {
		return nil
	}

	keys, ok := secret.Data["keys"].([]any)
	if !ok {
		return nil
	}

	for _, k := range keys {
		keyStr := k.(string)
		if before, ok0 := strings.CutSuffix(keyStr, "/"); ok0 {

			subPath := fmt.Sprintf("%s/%s", strings.TrimSuffix(currentPath, "/"), before)
			_ = c.walk(ctx, subPath, isV2, results)
		} else {
			// Leaf node secret
			leafPath := fmt.Sprintf("%s/%s", strings.TrimSuffix(currentPath, "/"), keyStr)

			// Fetch exact secret
			dataPath := leafPath
			if isV2 {
				// Convert mount/metadata/foo to mount/data/foo
				dataPath = strings.Replace(leafPath, "/metadata/", "/data/", 1)
			}
			s, err := c.client.Logical().ReadWithContext(ctx, dataPath)
			if err != nil || s == nil || s.Data == nil {
				log.Warn().Err(err).Str("path", dataPath).Msg("Failed to read secret")
				continue
			}

			// In KV v2, the actual KVs are under "data".
			var secretData map[string]any
			if isV2 {
				v2Data, exists := s.Data["data"].(map[string]any)
				if !exists {
					continue
				}
				secretData = v2Data
			} else {
				secretData = s.Data
			}

			var ownerStr string
			if ownerVal, ok := secretData["owner"]; ok {
				ownerStr = fmt.Sprintf("%v", ownerVal)
			}

			valBytes, _ := json.Marshal(secretData)

			var ttlPtr *int64
			if s.LeaseDuration > 0 {
				ttl := int64(s.LeaseDuration)
				ttlPtr = &ttl
			} else if ttlVal, ok := secretData["ttl"]; ok {
				switch v := ttlVal.(type) {
				case float64:
					ttl := int64(v)
					ttlPtr = &ttl
				case string:
					cleanV := v
					if before, ok0 := strings.CutSuffix(cleanV, "d"); ok0 {
						if val, err := strconv.Atoi(before); err == nil {
							cleanV = fmt.Sprintf("%dh", val*24) //nolint:mnd
						}
					}
					if d, err := time.ParseDuration(cleanV); err == nil {
						ttl := int64(d.Seconds())
						ttlPtr = &ttl
					} else if i, err := strconv.ParseInt(cleanV, 10, 64); err == nil {
						ttlPtr = &i
					}
				}
			}

			ext := ExtractedSecret{
				Path:       currentPath,
				Key:        keyStr,
				SecretType: "generic",
				Metadata:   valBytes,
				Owner:      ownerStr,
				TTL:        ttlPtr,
				Policies:   []string{},
			}

			*results = append(*results, ext)
		}
	}

	return nil
}
