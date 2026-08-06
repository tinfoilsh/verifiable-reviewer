package main

import (
	_ "embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

//go:embed reviewer-config.yml
var reviewerConfigYAML []byte // provider pins, attested as part of the binary

// ProviderPin is one entry of reviewer-config.yml: the exact inference
// endpoint and model a provider mode is allowed to use. The file ships
// inside the measured image, so these pins are attested.
type ProviderPin struct {
	Endpoint string `yaml:"endpoint"`
	Model    string `yaml:"model"`
}

type reviewerConfigFile struct {
	Providers map[string]ProviderPin `yaml:"providers"`
}

type Config struct {
	// Auth credentials supplied as Tinfoil secrets.
	TinfoilAPIKey  string // outbound, for the Tinfoil inference call
	OpenAIAPIKey   string // outbound, for the OpenAI call; empty disables provider "openai"
	ReviewerAPIKey string // inbound, required on /review

	// Provider pins loaded from reviewer-config.yml (baked into the image).
	Providers map[string]ProviderPin

	RekorURL string

	// In-container paths produced by boot. The TLS key and matching cert
	// are bind-mounted in by tinfoil-config.yml. The cert is the one
	// recorded in CT (with the attestation in its SAN extension); we hash
	// it so verifiers can locate the CT entry from the Rekor predicate.
	TLSKeyPath  string
	TLSCertPath string
}

func LoadConfig() (*Config, error) {
	tinfoilKey := os.Getenv("TINFOIL_API_KEY")
	if tinfoilKey == "" {
		return nil, fmt.Errorf("TINFOIL_API_KEY is required")
	}
	reviewerKey := os.Getenv("REVIEWER_API_KEY")
	if reviewerKey == "" {
		return nil, fmt.Errorf("REVIEWER_API_KEY is required")
	}
	openaiKey := os.Getenv("OPENAI_API_KEY")

	providers, err := loadProviderPins()
	if err != nil {
		return nil, err
	}
	if _, ok := providers["tinfoil"]; !ok {
		return nil, fmt.Errorf("reviewer-config.yml: provider %q is required", "tinfoil")
	}
	if openaiKey != "" {
		if _, ok := providers["openai"]; !ok {
			return nil, fmt.Errorf("reviewer-config.yml: OPENAI_API_KEY is set but provider %q is missing", "openai")
		}
	}

	return &Config{
		TinfoilAPIKey:  tinfoilKey,
		OpenAIAPIKey:   openaiKey,
		ReviewerAPIKey: reviewerKey,
		Providers:      providers,
		RekorURL:       envOr("REKOR_URL", "https://rekor.sigstore.dev"),
		TLSKeyPath:     envOr("TLS_KEY_PATH", "/tinfoil-app/tls.key"),
		TLSCertPath:    envOr("TLS_CERT_PATH", "/tinfoil-app/tls.crt"),
	}, nil
}

func loadProviderPins() (map[string]ProviderPin, error) {
	var parsed reviewerConfigFile
	if err := yaml.Unmarshal(reviewerConfigYAML, &parsed); err != nil {
		return nil, fmt.Errorf("parse reviewer-config.yml: %w", err)
	}
	for name, pin := range parsed.Providers {
		if pin.Endpoint == "" || pin.Model == "" {
			return nil, fmt.Errorf("reviewer-config.yml: provider %q needs both endpoint and model", name)
		}
	}
	return parsed.Providers, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
