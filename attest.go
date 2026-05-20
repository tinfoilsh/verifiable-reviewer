package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// Signer signs application bytes with the per-boot TLS private key. The key
// fingerprint is bound into the attestation report's report_data, so signatures
// chain back to attested code.
type Signer struct {
	key       *ecdsa.PrivateKey
	pubKeyDER []byte // SPKI DER, hash is the fingerprint
	attestDoc json.RawMessage
}

func NewSigner(cfg *Config) (*Signer, error) {
	key, err := loadECKey(cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading TLS key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling pubkey: %w", err)
	}

	attestBytes, err := os.ReadFile(cfg.AttestationPath)
	if err != nil {
		return nil, fmt.Errorf("reading attestation doc at %s: %w", cfg.AttestationPath, err)
	}
	var probe map[string]any
	if err := json.Unmarshal(attestBytes, &probe); err != nil {
		return nil, fmt.Errorf("attestation doc is not valid JSON: %w", err)
	}

	return &Signer{
		key:       key,
		pubKeyDER: pubDER,
		attestDoc: json.RawMessage(attestBytes),
	}, nil
}

// SignDigest signs a SHA-256 digest with the TLS private key, returning
// an ASN.1 DER ECDSA signature.
func (s *Signer) SignDigest(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

// KeyFingerprint returns sha256 of the SPKI DER encoding of the public key —
// matching the tls_key_fp value embedded in the attestation report's
// report_data.
func (s *Signer) KeyFingerprint() [32]byte {
	return sha256.Sum256(s.pubKeyDER)
}

// AttestationDoc returns the boot-time attestation document as raw JSON,
// for embedding verbatim into the in-toto predicate.
func (s *Signer) AttestationDoc() json.RawMessage {
	return s.attestDoc
}

// PublicKeyPEM returns the signing public key as a PEM-encoded SPKI block,
// suitable for the `verifiers` field on a Rekor DSSE entry.
func (s *Signer) PublicKeyPEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: s.pubKeyDER}), nil
}

func loadECKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	// cvmimage writes SEC1 ("EC PRIVATE KEY" PEM block); the PKCS#8 branch
	// is defensive in case that ever changes.
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key in %s is not ECDSA", path)
		}
		return ec, nil
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
