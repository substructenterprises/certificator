package main

import (
	"bytes"
	"os"

	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/certificate"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/vault"
)

func main() {
	logger := logrus.New()
	legoLog.Logger = logger

	cfg, err := config.LoadCertificateeConfig()
	if err != nil {
		logger.Fatal(err)
	}

	switch cfg.Log.Format {
	case "JSON":
		logger.SetFormatter(&logrus.JSONFormatter{})
	case "LOGFMT":
		logger.SetFormatter(&logrus.TextFormatter{})
	}

	switch cfg.Log.Level {
	case "DEBUG":
		logger.SetLevel(logrus.DebugLevel)
	case "INFO":
		logger.SetLevel(logrus.InfoLevel)
	case "WARN":
		logger.SetLevel(logrus.WarnLevel)
	case "ERROR":
		logger.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		logger.SetLevel(logrus.FatalLevel)
	}

	vaultClient, err := vault.NewVaultClient(cfg.Vault, cfg.Environment, logger)
	if err != nil {
		logger.Fatal(err)
	}

	var failedCertificates []string

	logger.Info(cfg.CertificateNames)

	for _, cert := range cfg.CertificateNames {

		certificatePath := cfg.CertificatePath + cert + cfg.CertificateExtension

		fileCert, err := loadFile(certificatePath)
		if err != nil {
			failedCertificates = append(failedCertificates, cert)
			logger.Error(err)
			continue
		}

		parsedVaultCert, parsedVaultKey, err := certificate.GetCertificateAndKey(cert, vaultClient)
		if err != nil {
			failedCertificates = append(failedCertificates, cert)
			logger.Error(err)
			continue
		}

		logger.Debugf("Parsed Vault Certificate: %v", parsedVaultCert)
		logger.Debugf("Parsed Vault Key: %v", parsedVaultKey)
		logger.Debugf("Combine Cert and Key: %v", cfg.CombineCertAndKey)

		composedVaultCert := certificate.ComposeCertificate(parsedVaultCert, parsedVaultKey, cfg.CombineCertAndKey)

		logger.Infof("comparing certificate for %s", cert)

		if !bytes.Equal(composedVaultCert, fileCert) {
			logger.Infof("deploying certificate for %s", cert)

			err = deployFile(certificatePath, composedVaultCert)
			if err != nil {
				failedCertificates = append(failedCertificates, cert)
				logger.Error(err)
				continue
			}
		} else {
			logger.Infof("certificate for %s matches vault, not replacing", cert)
		}

		if !cfg.CombineCertAndKey && cfg.KeyPath != "" {
			logger.Infof("comparing key for %s", cert)

			keyPath := cfg.KeyPath + cert + cfg.KeyExtension

			fileKey, err := loadFile(keyPath)
			if err != nil {
				failedCertificates = append(failedCertificates, cert)
				logger.Error(err)
				continue
			}

			composedVaultKey := certificate.ComposeKey(parsedVaultKey)

			if !bytes.Equal(fileKey, composedVaultKey) {
				logger.Infof("deploying key for %s", cert)

				err = deployFile(keyPath, composedVaultKey)
				if err != nil {
					failedCertificates = append(failedCertificates, cert)
					logger.Error(err)
					continue
				}
			} else {
				logger.Infof("key for %s matches vault, not replacing", cert)
			}
		}
	}

	if len(failedCertificates) > 0 {
		logger.Fatalf("Failed to deploy certificates for: %v", failedCertificates)
	}
}

func loadFile(path string) ([]byte, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func deployFile(path string, content []byte) error {

	err := os.WriteFile(path, content, 0600)
	if err != nil {
		return err
	}

	return nil

}
