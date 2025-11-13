package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	aulogging "github.com/StephanHCB/go-autumn-logging"
	baoapi "github.com/openbao/openbao/api/v2"
)

var (
	ErrClientNotInitialized = errors.New("OpenBao client not initialized")
	ErrInvalidConfig        = errors.New("invalid configuration")
	ErrNoSecretFound        = errors.New("no secret found at path")
	ErrUnexpectedDataFormat = errors.New("unexpected data format in KV v2 response")
	ErrNoClientToken        = errors.New("no client token returned from vault")
)

type Vault struct {
	config    *Config
	baoClient *baoapi.Client

	// thread-safe token handling
	tokenMu sync.RWMutex
}

func New(
	config *Config,
	client *http.Client,
) (*Vault, error) {
	if client == nil {
		client = http.DefaultClient
	}

	baoConfig := baoapi.DefaultConfig()
	baoConfig.Address = config.ServerURL
	baoConfig.HttpClient = client

	baoClient, err := baoapi.NewClient(baoConfig)
	if err != nil {
		return nil, err
	}

	if config.AuthToken != "" && baoClient != nil {
		baoClient.SetToken(config.AuthToken)
	}

	return &Vault{
		config:    config,
		baoClient: baoClient,
	}, nil
}

func (v *Vault) FetchSecretsToEnv(ctx context.Context) error {
	for path, secretsConfig := range v.config.SecretsConfig {
		secrets, err := v.FetchSecrets(ctx, path)
		if err != nil {
			return err
		}
		for _, secretConfig := range secretsConfig {
			vaultKey := secretConfig.VaultKey
			if secret, ok := secrets[vaultKey]; ok {
				envVar := secretConfig.VaultKey
				if secretConfig.EnvVar != nil && *secretConfig.EnvVar != "" {
					envVar = *secretConfig.EnvVar
				}
				if err = os.Setenv(envVar, secret); err != nil {
					return fmt.Errorf("failed to set env var %s for vault key %s from vault path %s: %w", envVar, vaultKey, path, err)
				}
			} else {
				return fmt.Errorf("failed to find vault key %s at vault path %s", vaultKey, path)
			}
		}
	}
	return nil
}

func (v *Vault) FetchSecrets(ctx context.Context, secretsPath string) (map[string]string, error) {
	aulogging.Logger.Ctx(ctx).Info().Printf("querying vault for secrets at %s", secretsPath)

	if v.baoClient == nil {
		return nil, ErrClientNotInitialized
	}

	// Ensure we have a valid token
	if err := v.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure valid token: %w", err)
	}

	secret, err := v.baoClient.Logical().ReadWithContext(ctx, secretsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secrets from vault: %w", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoSecretFound, secretsPath)
	}

	var secretData map[string]interface{}
	if dataField, ok := secret.Data["data"]; ok {
		if dataMap, ok := dataField.(map[string]interface{}); ok {
			secretData = dataMap
		} else {
			return nil, ErrUnexpectedDataFormat
		}
	} else {
		secretData = secret.Data
	}

	result := make(map[string]string)
	for key, val := range secretData {
		if strVal, ok := val.(string); ok {
			result[key] = strVal
		} else {
			result[key] = fmt.Sprintf("%v", val)
		}
	}

	return result, nil
}

// ensureToken checks if a token exists and refreshes if needed
func (v *Vault) ensureToken(ctx context.Context) error {
	v.tokenMu.RLock()
	hasToken := v.baoClient.Token() != ""
	v.tokenMu.RUnlock()

	if !hasToken {
		return v.refreshAuthToken(ctx)
	}

	return nil
}

func (v *Vault) refreshAuthToken(ctx context.Context) error {
	v.tokenMu.Lock()
	defer v.tokenMu.Unlock()

	if v.baoClient.Token() != "" {
		return nil
	}

	if v.config.AuthToken != "" {
		v.baoClient.SetToken(v.config.AuthToken)
		return nil
	}

	aulogging.Logger.Ctx(ctx).Info().Print("authenticating with vault")

	k8sTokenBytes, err := os.ReadFile(v.config.AuthKubernetesTokenPath)
	if err != nil {
		return fmt.Errorf("unable to read vault token file: %w", err)
	}

	authPath := fmt.Sprintf("auth/%s/login", v.config.AuthKubernetesBackend)
	secret, err := v.baoClient.Logical().WriteWithContext(ctx, authPath, map[string]interface{}{
		"jwt":  string(k8sTokenBytes),
		"role": v.config.AuthKubernetesRole,
	})
	if err != nil {
		return fmt.Errorf("kubernetes auth failed: %w", err)
	}

	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return fmt.Errorf("no client token returned from vault")
	}

	v.baoClient.SetToken(secret.Auth.ClientToken)

	aulogging.Logger.Ctx(ctx).Info().Print("successfully authenticated with vault")
	return nil
}
