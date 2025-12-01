package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"go.yaml.in/yaml/v4"
)

// Acme contains acme related configuration parameters
type Acme struct {
	AccountEmail              string `envconfig:"ACME_ACCOUNT_EMAIL" default:""`
	DNSChallengeProvider      string `envconfig:"ACME_DNS_CHALLENGE_PROVIDER" default:""`
	DNSPropagationRequirement bool   `envconfig:"ACME_DNS_PROPAGATION_REQUIREMENT" default:"true"`
	ReregisterAccount         bool   `envconfig:"ACME_REREGISTER_ACCOUNT" default:"false"`
	ServerURL                 string `envconfig:"ACME_SERVER_URL" default:"https://acme-staging-v02.api.letsencrypt.org/directory"`
	EABKid                    string `envconfig:"ACME_EAB_KID"`
	EABHmacKey                string `envconfig:"ACME_EAB_HMAC_KEY"`
}

// Vault contains vault related configuration parameters
type Vault struct {
	ApproleRoleID   string `envconfig:"VAULT_APPROLE_ROLE_ID"`
	ApproleSecretID string `envconfig:"VAULT_APPROLE_SECRET_ID"`
	Token           string `envconfig:"VAULT_TOKEN"`
	KVStoragePath   string `envconfig:"VAULT_KV_STORAGE_PATH" default:"secret/data/certificator/"`
}

type Log struct {
	Format string `envconfig:"LOG_FORMAT" default:"JSON"`
	Level  string `envconfig:"LOG_LEVEL" default:"INFO"`
}

// Config contains all configuration parameters
type Config struct {
	Acme            Acme
	Vault           Vault
	Log             Log
	Certificatee    Certificatee
	DNSAddress      string   `envconfig:"DNS_ADDRESS" default:"127.0.0.1:53"`
	Environment     string   `envconfig:"ENVIRONMENT" default:"prod"`
	DomainsFile     string   `envconfig:"CERTIFICATOR_DOMAINS_FILE" default:"/code/domains.yml"`
	DomainsList     []string `envconfig:"CERTIFICATOR_DOMAINS_LIST"`
	RenewBeforeDays int      `envconfig:"CERTIFICATOR_RENEW_BEFORE_DAYS" default:"30"`
	Domains         []string
}

// Configuration values specific to the certificatee tool
type Certificatee struct {
	CertificatePath      string   `envconfig:"CERTIFICATEE_CERTIFICATE_PATH" default:""`
	CertificateExtension string   `envconfig:"CERTIFICATEE_CERTIFICATE_EXTENSION" default:".pem"`
	KeyPath              string   `envconfig:"CERTIFICATEE_KEY_PATH" default:""`
	KeyExtension         string   `envconfig:"CERTIFICATEE_KEY_EXTENSION" default:".pem"`
	CombineCertAndKey    bool     `envconfig:"CERTIFICATEE_COMBINE_CERT_AND_KEY" default:"true"`
	CertificateNames     []string `envconfig:"CERTIFICATEE_DOMAINS_LIST" default:""`
}

// LoadConfig loads configuration options to  variable
func LoadConfig() (Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("failed getting config from env: %w", err)
	}

	if len(cfg.DomainsList) > 0 {
		cfg.Domains = cfg.DomainsList

		return cfg, err
	} else {
		cfg.Domains, err = parseDomainsFile(cfg.DomainsFile)
		if err != nil {
			return Config{}, err
		}

		return cfg, err
	}
}

// LoadConfig loads configuration options to  variable
func LoadCertificateeConfig() (Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("failed getting config from env: %w", err)
	}

	if len(cfg.Certificatee.CertificateNames) == 0 && cfg.Certificatee.CertificatePath != "" {
		cfg.Certificatee.CertificateNames, err = getCertificateNamesFromFiles(cfg.Certificatee.CertificatePath, cfg.Certificatee.CertificateExtension)
		if err != nil {
			return cfg, err
		}
	}
	return cfg, err
}

func parseDomainsFile(domainsFile string) ([]string, error) {
	f, err := os.Open(domainsFile)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", domainsFile, err)
	}

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading content of %s: %w", domainsFile, err)
	}

	var contentMap map[string]interface{}

	if err := yaml.Unmarshal(content, &contentMap); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", domainsFile, err)
	}

	var domains []string

	for _, v := range contentMap["domains"].([]interface{}) {
		domains = append(domains, v.(string))
	}

	return domains, nil
}

func getCertificateNamesFromFiles(path string, certificateExtension string) ([]string, error) {
	var certificateNames []string

	certDirFiles, err := os.ReadDir(path)
	if err != nil {
		return certificateNames, err
	}

	for _, certDirFile := range certDirFiles {
		fileExtension := filepath.Ext(certDirFile.Name())
		if certificateExtension == fileExtension {
			certificateName := strings.TrimSuffix(certDirFile.Name(), certificateExtension)
			certificateNames = append(certificateNames, certificateName)
		}
	}

	return certificateNames, nil
}
