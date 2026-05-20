package main

import (
	"fmt"
	"os"
)

type Config struct {
	ListenAddr string

	// Auth credentials supplied as Tinfoil secrets.
	TinfoilAPIKey  string // outbound, for the LLM call
	ReviewerAPIKey string // inbound, required on /review

	LLMURL   string
	LLMModel string
	RekorURL string

	// In-container paths produced by boot. TLSKeyPath is only present
	// when tinfoil-config has enable-app-signing: true. AttestationPath
	// is the boot-time attestation document; both live under /tinfoil
	// (bind-mounted read-only by the shim).
	TLSKeyPath      string
	AttestationPath string
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
		ListenAddr:     envOr("LISTEN_ADDR", ":8080"),
		TinfoilAPIKey:  tinfoilKey,
		ReviewerAPIKey: reviewerKey,
		LLMURL:         envOr("LLM_URL", "https://inference.tinfoil.sh/v1/chat/completions"),
		LLMModel:       envOr("LLM_MODEL", "gpt-oss-120b"),
		RekorURL:       envOr("REKOR_URL", "https://rekor.sigstore.dev"),
		TLSKeyPath:      envOr("TLS_KEY_PATH", "/tinfoil/tls.key"),
		AttestationPath: envOr("ATTESTATION_PATH", "/tinfoil/attestation.json"),
	}, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
