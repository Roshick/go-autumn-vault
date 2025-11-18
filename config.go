package vault

import (
	"encoding/json"
	"reflect"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	Disabled                bool          `env:"VAULT_DISABLED" envDefault:"false"`
	ServerURL               string        `env:"VAULT_URL"`
	AuthToken               string        `env:"VAULT_AUTH_TOKEN"`
	AuthKubernetesRole      string        `env:"VAULT_AUTH_KUBERNETES_ROLE"`
	AuthKubernetesTokenPath string        `env:"VAULT_AUTH_KUBERNETES_TOKEN_PATH" envDefault:"/var/run/secrets/kubernetes.io/serviceaccount/token"`
	AuthKubernetesBackend   string        `env:"VAULT_AUTH_KUBERNETES_BACKEND"`
	SecretsConfig           SecretsConfig `env:"VAULT_SECRETS_CONFIG" envDefault:"{}"`
}

type SecretsConfig map[string][]SecretConfig

type SecretConfig struct {
	VaultKey string  `json:"vaultKey"`
	EnvVar   *string `json:"envVar,omitempty"`
}

func NewConfig() *Config {
	return &Config{}
}

func (c *Config) ObtainValuesFromEnv() error {
	return env.ParseWithOptions(c, env.Options{
		FuncMap: map[reflect.Type]env.ParserFunc{
			// register parser for the non-pointer SecretsConfig type
			reflect.TypeOf(SecretsConfig{}): func(v string) (any, error) {
				return parseSecretsConfig(v)
			},
		},
	})
}

func parseSecretsConfig(value string) (SecretsConfig, error) {
	var secretsConfig SecretsConfig
	if err := json.Unmarshal([]byte(value), &secretsConfig); err != nil {
		return nil, err
	}
	return secretsConfig, nil
}
