package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Signer signs application bytes with the per-boot TLS private key. The
// matching cert is logged in CT — we record its sha256 so verifiers can locate
// the CT entry from the Rekor predicate
type Signer struct {
	key        *ecdsa.PrivateKey
	pubKeyDER  []byte   // SPKI DER, hash is the tls_key_fp
	certSHA256 [32]byte // sha256 of the cert DER
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

	certDER, err := loadCertDER(cfg.TLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("loading TLS cert: %w", err)
	}

	return &Signer{
		key:        key,
		pubKeyDER:  pubDER,
		certSHA256: sha256.Sum256(certDER),
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

// CertSHA256 returns sha256 of the leaf cert's DER encoding — the same
// fingerprint crt.sh / openssl x509 -fingerprint -sha256 produce.
func (s *Signer) CertSHA256() [32]byte {
	return s.certSHA256
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

func loadCertDER(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block in %s, got %q", path, block.Type)
	}
	return block.Bytes, nil
}
