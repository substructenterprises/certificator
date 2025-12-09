# Certificatee

A tool that compares file-based PEM certificates with certificates deployed to Vault by Certificator, and then updates the file if they differ.

## Usage

1. Set necessary environment variables (see [configuration](#Configuration)), including Certificatee-specific variables.
1. Run certificatee
1. Find certificate files in directory

## Configuration

Certificatee reads most configuration parameters from environment variables, and shares many of the same environment variables with Certificator.
They are defined in [pkg/config/config.go](pkg/config/config.go) Certificatee struct

Configuration variables:
- `VAULT_APPROLE_ROLE_ID` - role ID for Vault approle authentication method. **Required in prod env if VAULT_TOKEN is not set**
- `VAULT_APPROLE_SECRET_ID` - secret ID for Vault approle authentication method. **Required in prod env if VAULT_TOKEN is not set**
- `VAULT_TOKEN` - token for Vault JWT authentication method - if set, use the JWT auth method with this token to authenticate against Vault.
- `VAULT_KV_STORAGE_PATH` - path in Vault KV storage where certificator stores certificates and account data. Default: secret/data/certificator/
- `VAULT_ADDR` sets vault address, example: "http://localhost:8200". **Required**
- `LOG_FORMAT` - logging format, supported formats - JSON and LOGFMT. Default: JSON
- `LOG_LEVEL` - logging level, supported levels - DEBUG, INFO, WARN, ERROR, FATAL. Default: INFO.
- `ENVIRONMENT` - sets an environment where the certificator is running. If the environment is dev it uses token set in `VAULT_DEV_ROOT_TOKEN_ID` env variable to authenticate in Vault. If the environment is prod it uses an approle authentication method. Default: prod
- `CERTIFICATEE_CERTIFICATE_PATH` - path to the certificates. **Required**
- `CERTIFICATEE_CERTIFICATE_EXTENSION` - certificate extension. Default: `.pem`.
- `CERTIFICATEE_COMBINE_CERT_AND_KEY` - whether the private key should be added to the certificate. Default: `true`.
- `CERTIFICATEE_KEY_PATH` - path to the private keys, **required** if `CERTIFICATEE_COMBINE_CERT_AND_KEY` is set.
- `CERTIFICATEE_KEY_EXTENSION` - private key file extension, if `CERTIFICATEE_COMBINE_CERT_AND_KEY` is set. Default: `.pem`.
- `CERTIFICATEE_DOMAINS_LIST` - list of domains for which certificates should be renewed. If this is not set then Certificatee will try to check all certificates in `CERTIFICATEE_CERTIFICATE_PATH`.


## Tests

Certificatee is tested alongside Certificator.
