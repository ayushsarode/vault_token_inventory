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

const hoursInDay = 24

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

func NewVaultClient(addr, token, mount string) (*VaultClient, error) {
	config := api.DefaultConfig()
	config.Address = addr

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	if token == "" {
		return nil, errors.New("no valid token provided")
	}
	client.SetToken(token)

	return &VaultClient{
		client: client,
		mount:  mount,
	}, nil
}

func (c *VaultClient) FetchAll(ctx context.Context) ([]ExtractedSecret, error) {
	isV2 := c.detectKVType()

	var allSecrets []ExtractedSecret

	basePath := c.mount
	if isV2 {
		basePath = c.mount + "/metadata"
	}

	c.walk(ctx, basePath, isV2, &allSecrets)
	return allSecrets, nil
}

func (c *VaultClient) detectKVType() bool {
	mounts, err := c.client.Sys().ListMounts()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to check sys/mounts permissions (defaulting to KV v2)")
		return true
	}

	mountPath := c.mount
	if mountPath != "" && !strings.HasSuffix(mountPath, "/") {
		mountPath += "/"
	}

	if mountInfo, ok := mounts[mountPath]; ok {
		if version, exists := mountInfo.Options["version"]; exists && version == "1" {
			log.Info().Str("mount", c.mount).Msg("Dynamic detection: KV Type Version 1")
			return false
		}
		log.Info().Str("mount", c.mount).Msg("Dynamic detection: KV Type Version 2")
	} else {
		log.Warn().Str("mount", mountPath).Msg("Mount path not found in sys/mounts (defaulting to KV v2)")
	}
	return true
}

func (c *VaultClient) FetchTokens(ctx context.Context) ([]ExtractedSecret, error) {
	var results []ExtractedSecret

	secret, err := c.client.Logical().ListWithContext(ctx, "auth/token/accessors")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list token accessors (requires sudo/root)")
		return results, nil
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

		if ext := c.fetchSingleToken(ctx, accessor); ext != nil {
			results = append(results, *ext)
		}
	}

	return results, nil
}

func (c *VaultClient) fetchSingleToken(ctx context.Context, accessor string) *ExtractedSecret {
	s, err := c.client.Logical().WriteWithContext(ctx, "auth/token/lookup-accessor", map[string]any{
		"accessor": accessor,
	})
	if err != nil || s == nil || s.Data == nil {
		log.Warn().Str("accessor", accessor).Msg("Failed to lookup token accessor")
		return nil
	}

	var ttlPtr *int64
	if ttlVal, ok := s.Data["ttl"]; ok {
		ttlPtr = parseTTLValue(ttlVal)
	}

	valBytes, _ := json.Marshal(s.Data)

	return &ExtractedSecret{
		Path:       "auth/token/accessors",
		Key:        accessor,
		SecretType: "vault_token",
		Metadata:   valBytes,
		TTL:        ttlPtr,
	}
}

func (c *VaultClient) walk(ctx context.Context, currentPath string, isV2 bool, results *[]ExtractedSecret) {
	log.Debug().Str("path", currentPath).Msg("Walking Vault path")

	secret, err := c.client.Logical().ListWithContext(ctx, currentPath)
	if err != nil {
		log.Warn().Err(err).Str("path", currentPath).Msg("Failed to list path (permission denied?)")
		return
	}
	if secret == nil || secret.Data == nil {
		return
	}

	keys, ok := secret.Data["keys"].([]any)
	if !ok {
		return
	}

	trimmedPath := strings.TrimSuffix(currentPath, "/")

	for _, k := range keys {
		keyStr, ok := k.(string)
		if !ok {
			continue
		}
		if before, ok0 := strings.CutSuffix(keyStr, "/"); ok0 {
			c.walk(ctx, trimmedPath+"/"+before, isV2, results)
		} else {
			c.processLeafNode(ctx, trimmedPath, keyStr, isV2, currentPath, results)
		}
	}
}

func (c *VaultClient) processLeafNode(ctx context.Context, trimmedPath, keyStr string, isV2 bool, currentPath string, results *[]ExtractedSecret) {
	leafPath := trimmedPath + "/" + keyStr

	dataPath := leafPath
	if isV2 {
		dataPath = strings.Replace(leafPath, "/metadata/", "/data/", 1)
	}
	s, secretData := c.fetchSecretData(ctx, dataPath, isV2)
	if secretData == nil {
		return
	}

	var customMeta map[string]any
	if isV2 {
		customMeta = c.readCustomMeta(ctx, leafPath)
	}

	valBytes, ownerStr := buildSecretMetadata(secretData, customMeta)

	var ttlPtr *int64
	if s.LeaseDuration > 0 {
		ttl := int64(s.LeaseDuration)
		ttlPtr = &ttl
	} else if ttlVal, ok := secretData["ttl"]; ok {
		ttlPtr = parseTTLValue(ttlVal)
	} else if ttlVal, ok := customMeta["ttl"]; ok {
		ttlPtr = parseTTLValue(ttlVal)
	}

	canonicalPath := currentPath
	if isV2 {
		canonicalPath = strings.Replace(currentPath, "/metadata", "", 1)
	}

	ext := ExtractedSecret{
		Path:       canonicalPath,
		Key:        keyStr,
		SecretType: "generic",
		Metadata:   valBytes,
		Owner:      ownerStr,
		TTL:        ttlPtr,
		Policies:   []string{},
	}

	*results = append(*results, ext)
}

func (c *VaultClient) fetchSecretData(ctx context.Context, dataPath string, isV2 bool) (*api.Secret, map[string]any) {
	s, err := c.client.Logical().ReadWithContext(ctx, dataPath)
	if err != nil {
		log.Debug().Err(err).Str("path", strings.ToLower(dataPath)).Msg("Skipping secret: no version data (deleted or empty)")
		return nil, nil
	}
	if s == nil || s.Data == nil {
		log.Debug().Str("path", strings.ToLower(dataPath)).Msg("Skipping secret: nil response from Vault")
		return nil, nil
	}

	if isV2 {
		v2Data, exists := s.Data["data"].(map[string]any)
		if !exists {
			return nil, nil
		}
		return s, v2Data
	}
	return s, s.Data
}

func (c *VaultClient) readCustomMeta(ctx context.Context, leafPath string) map[string]any {
	if metaSecret, metaErr := c.client.Logical().ReadWithContext(ctx, leafPath); metaErr == nil && metaSecret != nil {
		if cm, ok := metaSecret.Data["custom_metadata"].(map[string]any); ok {
			return cm
		}
	}
	return nil
}

func buildSecretMetadata(secretData, customMeta map[string]any) ([]byte, string) {
	metadata := map[string]any{
		"keys_count": len(secretData),
	}
	for _, field := range []string{"owner", "team", "environment", "service", "ttl", "description"} {
		if val, exists := secretData[field]; exists {
			metadata[field] = val
		} else if val, exists := customMeta[field]; exists {
			metadata[field] = val
		}
	}

	var ownerStr string
	if ownerVal, ok := metadata["owner"]; ok {
		ownerStr = fmt.Sprintf("%v", ownerVal)
	}

	valBytes, _ := json.Marshal(metadata)
	return valBytes, ownerStr
}

func parseTTLValue(val any) *int64 {
	switch v := val.(type) {
	case float64:
		if v > 0 {
			ttl := int64(v)
			return &ttl
		}
	case json.Number:
		if ttl, err := v.Int64(); err == nil && ttl > 0 {
			return &ttl
		}
	case string:
		return parseStringTTL(v)
	}
	return nil
}

func parseStringTTL(v string) *int64 {
	clean := v
	if before, ok := strings.CutSuffix(clean, "d"); ok {
		if days, err := strconv.Atoi(before); err == nil {
			clean = fmt.Sprintf("%dh", days*hoursInDay)
		}
	}
	if d, err := time.ParseDuration(clean); err == nil {
		ttl := int64(d.Seconds())
		return &ttl
	}
	if i, err := strconv.ParseInt(clean, 10, 64); err == nil && i > 0 {
		return &i
	}
	return nil
}
