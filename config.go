package main

import (
	"fmt"
	"os"
)

type Config struct {
	// Auth credentials supplied as Tinfoil secrets.
	TinfoilAPIKey  string // outbound, for the LLM call
	ReviewerAPIKey string // inbound, required on /review

	LLMModel string
	RekorURL string

	// In-container paths produced by boot. The TLS key and matching cert
	// are bind-mounted in by tinfoil-config.yml. The cert is the one
	// recorded in CT (with the attestation in its SAN extension); we hash
	// it so verifiers can locate the CT entry from the Rekor predicate.
	TLSKeyPath  string
	TLSCertPath string

	// Attestation document from the CVM's public ramdisk (mounted at /tinfoil).
	// Published to Rekor once per boot so verifiers can retrieve the historical
	// attestation without a live enclave.
	AttestationPath string

	// Writable directory for the boot-attestation flag file.
	StateDir string
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

	return &Config{
		TinfoilAPIKey:  tinfoilKey,
		ReviewerAPIKey: reviewerKey,
		LLMModel:       envOr("LLM_MODEL", "gpt-oss-120b"),
		RekorURL:       envOr("REKOR_URL", "https://rekor.sigstore.dev"),
		TLSKeyPath:      envOr("TLS_KEY_PATH", "/tinfoil-app/tls.key"),
		TLSCertPath:     envOr("TLS_CERT_PATH", "/tinfoil-app/tls.crt"),
		AttestationPath: envOr("ATTESTATION_PATH", "/tinfoil/attestation.json"),
		StateDir:        envOr("STATE_DIR", "/var/lib/verifiable-reviewer"),
	}, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
