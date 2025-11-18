package config

import (
	"os"
	"strconv"
	"testing"

	"github.com/thanos-io/thanos/pkg/testutil"
)

func TestDefaultConfig(t *testing.T) {
	resetEnvVars()

	var expectedConf = Config{
		Acme: Acme{
			AccountEmail:              "test@test.com",
			DNSChallengeProvider:      "exec",
			DNSPropagationRequirement: true,
			ReregisterAccount:         false,
			ServerURL:                 "https://acme-staging-v02.api.letsencrypt.org/directory",
		},
		Vault: Vault{
			ApproleRoleID:   "",
			ApproleSecretID: "",
			KVStoragePath:   "secret/data/certificator/",
		},
		Log: Log{
			Format: "JSON",
			Level:  "INFO",
		},
		DNSAddress:      "127.0.0.1:53",
		Environment:     "prod",
		DomainsFile:     "../../domains.yml",
		Domains:         []string{"mydomain.com,www.mydomain.com", "example.com"},
		DomainsList:     nil,
		RenewBeforeDays: 30,
	}

	conf, err := LoadConfig()
	testutil.Ok(t, err)
	testutil.Equals(t, expectedConf, conf)
}

func TestConfig_WithDomainsFile(t *testing.T) {
	var (
		reregisterAcc        = true
		acmeServerURL        = "http://someserver"
		dnsChallengeProvider = "other"
		dnsPropagationReq    = false
		vaultRoleID          = "role"
		vaultSecretID        = "secret"
		vaultKVStorePath     = "secret/path"
		logFormat            = "LOGFMT"
		logLevel             = "DEBUG"
		dnsAddress           = "1.1.1.1:53"
		environment          = "test"
		renewBeforeDays      = 60

		expectedConf = Config{
			Acme: Acme{
				AccountEmail:              "test@test.com",
				DNSChallengeProvider:      dnsChallengeProvider,
				DNSPropagationRequirement: dnsPropagationReq,
				ReregisterAccount:         reregisterAcc,
				ServerURL:                 acmeServerURL,
			},
			Vault: Vault{
				ApproleRoleID:   vaultRoleID,
				ApproleSecretID: vaultSecretID,
				KVStoragePath:   vaultKVStorePath,
			},
			Log: Log{
				Format: logFormat,
				Level:  logLevel,
			},
			DNSAddress:      dnsAddress,
			Environment:     environment,
			DomainsFile:     "../../domains.yml",
			Domains:         []string{"mydomain.com,www.mydomain.com", "example.com"},
			DomainsList:     nil,
			RenewBeforeDays: renewBeforeDays,
		}
	)

	resetEnvVars()

	_ = os.Setenv("ACME_REREGISTER_ACCOUNT", strconv.FormatBool(reregisterAcc))
	_ = os.Setenv("ACME_SERVER_URL", acmeServerURL)
	_ = os.Setenv("ACME_DNS_CHALLENGE_PROVIDER", dnsChallengeProvider)
	_ = os.Setenv("ACME_DNS_PROPAGATION_REQUIREMENT", strconv.FormatBool(dnsPropagationReq))
	_ = os.Setenv("VAULT_APPROLE_ROLE_ID", vaultRoleID)
	_ = os.Setenv("VAULT_APPROLE_SECRET_ID", vaultSecretID)
	_ = os.Setenv("VAULT_KV_STORAGE_PATH", vaultKVStorePath)
	_ = os.Setenv("LOG_FORMAT", logFormat)
	_ = os.Setenv("LOG_LEVEL", logLevel)
	_ = os.Setenv("DNS_ADDRESS", dnsAddress)
	_ = os.Setenv("ENVIRONMENT", environment)
	_ = os.Setenv("CERTIFICATOR_RENEW_BEFORE_DAYS", strconv.Itoa(renewBeforeDays))

	conf, err := LoadConfig()
	testutil.Ok(t, err)
	testutil.Equals(t, expectedConf, conf)
}

func TestConfig_WithDomainsList(t *testing.T) {
	var (
		reregisterAcc        = true
		acmeServerURL        = "http://someserver"
		dnsChallengeProvider = "other"
		dnsPropagationReq    = false
		vaultRoleID          = "role"
		vaultSecretID        = "secret"
		vaultKVStorePath     = "secret/path"
		logFormat            = "LOGFMT"
		logLevel             = "DEBUG"
		dnsAddress           = "1.1.1.1:53"
		environment          = "test"
		renewBeforeDays      = 60

		expectedConf = Config{
			Acme: Acme{
				AccountEmail:              "test@test.com",
				DNSChallengeProvider:      dnsChallengeProvider,
				DNSPropagationRequirement: dnsPropagationReq,
				ReregisterAccount:         reregisterAcc,
				ServerURL:                 acmeServerURL,
			},
			Vault: Vault{
				ApproleRoleID:   vaultRoleID,
				ApproleSecretID: vaultSecretID,
				KVStoragePath:   vaultKVStorePath,
			},
			Log: Log{
				Format: logFormat,
				Level:  logLevel,
			},
			DNSAddress:      dnsAddress,
			Environment:     environment,
			DomainsFile:     "../../domains.yml",
			DomainsList:     []string{"mydomain.com", "www.mydomain.com", "example.com"},
			Domains:         []string{"mydomain.com", "www.mydomain.com", "example.com"},
			RenewBeforeDays: renewBeforeDays,
		}
	)

	resetEnvVars()

	_ = os.Setenv("ACME_REREGISTER_ACCOUNT", strconv.FormatBool(reregisterAcc))
	_ = os.Setenv("ACME_SERVER_URL", acmeServerURL)
	_ = os.Setenv("ACME_DNS_CHALLENGE_PROVIDER", dnsChallengeProvider)
	_ = os.Setenv("ACME_DNS_PROPAGATION_REQUIREMENT", strconv.FormatBool(dnsPropagationReq))
	_ = os.Setenv("VAULT_APPROLE_ROLE_ID", vaultRoleID)
	_ = os.Setenv("VAULT_APPROLE_SECRET_ID", vaultSecretID)
	_ = os.Setenv("VAULT_KV_STORAGE_PATH", vaultKVStorePath)
	_ = os.Setenv("LOG_FORMAT", logFormat)
	_ = os.Setenv("LOG_LEVEL", logLevel)
	_ = os.Setenv("DNS_ADDRESS", dnsAddress)
	_ = os.Setenv("ENVIRONMENT", environment)
	_ = os.Setenv("CERTIFICATOR_RENEW_BEFORE_DAYS", strconv.Itoa(renewBeforeDays))
	_ = os.Setenv("CERTIFICATOR_DOMAINS_LIST", "mydomain.com,www.mydomain.com,example.com")

	conf, err := LoadConfig()
	testutil.Ok(t, err)
	testutil.Equals(t, expectedConf, conf)
}

func resetEnvVars() {
	// Set required env vars
	_ = os.Setenv("ACME_ACCOUNT_EMAIL", "test@test.com")
	_ = os.Setenv("ACME_DNS_CHALLENGE_PROVIDER", "exec")
	_ = os.Setenv("CERTIFICATOR_DOMAINS_FILE", "../../domains.yml")

	for _, key := range []string{"ACME_REREGISTER_ACCOUNT",
		"ACME_SERVER_URL",
		"VAULT_APPROLE_ROLE_ID",
		"VAULT_APPROLE_SECRET_ID",
		"VAULT_KV_STORAGE_PATH",
		"LOG_FORMAT",
		"LOG_LEVEL",
		"DNS_ADDRESS",
		"ENVIRONMENT",
		"CERTIFICATOR_RENEW_BEFORE_DAYS",
	} {
		_ = os.Unsetenv(key)
	}
}
