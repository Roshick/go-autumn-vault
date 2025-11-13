package vault

import (
	"os"
	"testing"
)

func TestObtainValuesFromEnv_ParsesSecretsConfig(t *testing.T) {
	// arrange
	jsonConfig := `{"my/secret/path":[{"vaultKey":"password","envVar":"APP_PASSWORD"},{"vaultKey":"username"}]}`
	if err := os.Setenv("VAULT_SECRETS_CONFIG", jsonConfig); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer os.Unsetenv("VAULT_SECRETS_CONFIG")

	cfg := NewConfig()

	// act
	if err := cfg.ObtainValuesFromEnv(); err != nil {
		t.Fatalf("ObtainValuesFromEnv error: %v", err)
	}

	// assert
	secretsSlice, ok := cfg.SecretsConfig["my/secret/path"]
	if !ok {
		t.Fatalf("expected path key to exist in secrets config")
	}
	if len(secretsSlice) != 2 {
		t.Fatalf("expected 2 secrets config entries, got %d", len(secretsSlice))
	}
	if secretsSlice[0].VaultKey != "password" || secretsSlice[0].EnvVar == nil || *secretsSlice[0].EnvVar != "APP_PASSWORD" {
		t.Fatalf("first secret config did not parse correctly: %+v", secretsSlice[0])
	}
	if secretsSlice[1].VaultKey != "username" || secretsSlice[1].EnvVar != nil {
		t.Fatalf("second secret config did not parse correctly: %+v", secretsSlice[1])
	}
}

func TestObtainValuesFromEnv_DefaultEmptySecretsConfig(t *testing.T) {
	os.Unsetenv("VAULT_SECRETS_CONFIG")
	cfg := NewConfig()
	if err := cfg.ObtainValuesFromEnv(); err != nil {
		t.Fatalf("ObtainValuesFromEnv error: %v", err)
	}
	if len(cfg.SecretsConfig) != 0 {
		t.Fatalf("expected empty secrets config by default, got: %+v", cfg.SecretsConfig)
	}
}
