package vault

import (
	"encoding/json"
	"os"

	auconfigapi "github.com/StephanHCB/go-autumn-config-api"
)

const (
	DefaultKeyServer                  = "VAULT_SERVER"
	DefaultKeyCertificateFilePath     = "VAULT_CERTIFICATE_FILE_PATH"
	DefaultKeyAuthToken               = "VAULT_AUTH_TOKEN"
	DefaultKeyAuthKubernetesRole      = "VAULT_AUTH_KUBERNETES_ROLE"
	DefaultKeyAuthKubernetesTokenPath = "VAULT_AUTH_KUBERNETES_TOKEN_PATH"
	DefaultKeyAuthKubernetesBackend   = "VAULT_AUTH_KUBERNETES_BACKEND"
	DefaultKeySecretsConfig           = "VAULT_SECRETS_CONFIG"
)

type Config interface {
	Server() string
	PublicCertificate() []byte
	AuthToken() string
	AuthKubernetesRole() string
	AuthKubernetesTokenPath() string
	AuthKubernetesBackend() string
	SecretsConfig() SecretsConfig
}

type SecretsConfig map[string][]SecretConfig

type SecretConfig struct {
	VaultKey  string  `json:"vaultKey"`
	ConfigKey *string `json:"configKey,omitempty"`
}

type DefaultConfigImpl struct {
	vServer                  string
	vPublicCertificate       []byte
	vAuthToken               string
	vAuthKubernetesRole      string
	vAuthKubernetesTokenPath string
	vAuthKubernetesBackend   string
	vSecretsConfig           SecretsConfig
}

func NewDefaultConfig() *DefaultConfigImpl {
	return &DefaultConfigImpl{}
}

func (c *DefaultConfigImpl) Server() string {
	return c.vServer
}

func (c *DefaultConfigImpl) PublicCertificate() []byte {
	return c.vPublicCertificate
}

func (c *DefaultConfigImpl) AuthToken() string {
	return c.vAuthToken
}

func (c *DefaultConfigImpl) AuthKubernetesRole() string {
	return c.vAuthKubernetesRole
}

func (c *DefaultConfigImpl) AuthKubernetesTokenPath() string {
	return c.vAuthKubernetesTokenPath
}

func (c *DefaultConfigImpl) AuthKubernetesBackend() string {
	return c.vAuthKubernetesBackend
}

func (c *DefaultConfigImpl) SecretsConfig() SecretsConfig {
	return c.vSecretsConfig
}

func (c *DefaultConfigImpl) ConfigItems() []auconfigapi.ConfigItem {
	return []auconfigapi.ConfigItem{
		{
			Key:         DefaultKeyServer,
			EnvName:     DefaultKeyServer,
			Default:     "http://localhost",
			Description: "",
			Validate:    auconfigapi.ConfigNeedsNoValidation,
		},
		{
			Key:         DefaultKeyAuthToken,
			EnvName:     DefaultKeyAuthToken,
			Default:     "",
			Description: "authentication token used to fetch secrets.",
			Validate:    auconfigapi.ConfigNeedsNoValidation,
		},
		{
			Key:         DefaultKeyAuthKubernetesRole,
			EnvName:     DefaultKeyAuthKubernetesRole,
			Default:     "",
			Description: "role binding to use for vault kubernetes authentication.",
			Validate:    auconfigapi.ConfigNeedsNoValidation,
		},
		{
			Key:         DefaultKeyAuthKubernetesTokenPath,
			EnvName:     DefaultKeyAuthKubernetesTokenPath,
			Default:     "/var/run/secrets/kubernetes.io/serviceaccount/token",
			Description: "file path to the service-account token",
			Validate:    auconfigapi.ConfigNeedsNoValidation,
		},
		{
			Key:         DefaultKeyAuthKubernetesBackend,
			EnvName:     DefaultKeyAuthKubernetesBackend,
			Default:     "",
			Description: "authentication path for the kubernetes cluster",
			Validate:    auconfigapi.ConfigNeedsNoValidation,
		},
		{
			Key:         DefaultKeySecretsConfig,
			EnvName:     DefaultKeySecretsConfig,
			Default:     "{}",
			Description: "config consisting of vault paths and keys to fetch from the corresponding path. values will be written to the global config object.",
			Validate:    auconfigapi.ConfigNeedsNoValidation,
		},
	}
}

func (c *DefaultConfigImpl) ObtainValues(getter func(string) string) error {
	c.vServer = getter(DefaultKeyServer)
	if vPublicCertificate, err := loadPublicCertificate(getter(DefaultKeyCertificateFilePath)); err != nil {
		return err
	} else {
		c.vPublicCertificate = vPublicCertificate
	}
	c.vAuthToken = getter(DefaultKeyAuthToken)
	c.vAuthKubernetesRole = getter(DefaultKeyAuthKubernetesRole)
	c.vAuthKubernetesTokenPath = getter(DefaultKeyAuthKubernetesTokenPath)
	c.vAuthKubernetesBackend = getter(DefaultKeyAuthKubernetesBackend)
	if vSecretsConfig, err := parseSecretsConfig(getter(DefaultKeySecretsConfig)); err != nil {
		return err
	} else {
		c.vSecretsConfig = vSecretsConfig
	}

	return nil
}

func parseSecretsConfig(value string) (SecretsConfig, error) {
	var secretsConfig SecretsConfig
	if err := json.Unmarshal([]byte(value), &secretsConfig); err != nil {
		return nil, err
	}
	return secretsConfig, nil
}

func loadPublicCertificate(filepath string) ([]byte, error) {
	if filepath != "" {
		publicCertBytes, err := os.ReadFile(filepath)
		if err != nil {
			return nil, err
		}
		return publicCertBytes, nil
	} else {
		return nil, nil
	}
}
