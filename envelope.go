package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	inTotoStatementType       = "https://in-toto.io/Statement/v0.1"
	inTotoPayloadType         = "application/vnd.in-toto+json"
	predicateType             = "https://tinfoil.sh/predicate/code-review/v1"
	attestationPredicateType  = "https://tinfoil.sh/predicate/enclave-attestation/v1"
)

// inTotoStatement is the SLSA-style envelope payload: subject names what was
// attested, predicate carries the body, predicateType identifies the schema.
type inTotoStatement struct {
	Type          string          `json:"_type"`
	Subject       []inTotoSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     reviewPredicate `json:"predicate"`
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// attestationDoc mirrors verifier.Document{Format,Body} from tinfoil-go.
// We only need these two fields to compute the .hatt. hash.
type attestationDoc struct {
	Format string `json:"format"`
	Body   string `json:"body"`
}

// attestationPredicate carries the full attestation document alongside the
// cert fingerprint and its hash, so a verifier can confirm the document
// matches the .hatt. SAN in the CT-logged cert without a live enclave.
type attestationPredicate struct {
	CertSHA256      string          `json:"cert_sha256"`
	AttestationHash string          `json:"attestation_hash"`
	Attestation     json.RawMessage `json:"attestation"`
}

type attestationStatement struct {
	Type          string                `json:"_type"`
	Subject       []inTotoSubject       `json:"subject"`
	PredicateType string                `json:"predicateType"`
	Predicate     attestationPredicate  `json:"predicate"`
}

type reviewPredicate struct {
	Repo               string   `json:"repo"`
	PrevTag            string   `json:"prev_tag"`
	CurrentTag         string   `json:"current_tag"`
	DiffSHA256         string   `json:"diff_sha256"`
	DiffBytes          int      `json:"diff_bytes"`
	ReviewText         string   `json:"review_text"`
	Malicious          string   `json:"malicious"`
	MaliciousReasoning string   `json:"malicious_reasoning"`
	Model              string   `json:"model"`
	Truncated          bool     `json:"truncated"`
	OmittedFiles       []string `json:"omitted_files,omitempty"`
	Timestamp          string   `json:"ts"`
	CertSHA256         string   `json:"cert_sha256"`
}

// dsseEnvelope is the on-the-wire DSSE format (Dead Simple Signing Envelope).
type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"` // base64
	Signatures  []dsseSignature `json:"signatures"`
}

// dsseSignature: we never set KeyID (rekor's intoto v0.0.1 dsse verifier
// uses a single-keyed wrapper that matches sigs by *empty* keyid — any
// non-empty value silently makes the sig unverifiable). `omitempty` keeps
// the field out of the marshaled envelope entirely.
type dsseSignature struct {
	Sig   string `json:"sig"` // base64
	KeyID string `json:"keyid,omitempty"`
}

// Publisher signs review attestations and pushes them to a Rekor instance.
type Publisher struct {
	signer     *Signer
	rekorURL   string
	httpClient *http.Client
}

func NewPublisher(signer *Signer, rekorURL string) *Publisher {
	return &Publisher{
		signer:     signer,
		rekorURL:   rekorURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// ReviewInput is everything envelope.go needs from the caller to build a
// statement: identity of what was reviewed plus the LLM's result.
type ReviewInput struct {
	Repo       string
	PrevTag    string
	CurrentTag string
	DiffBytes  []byte
	Result     *ReviewResult
}

// SignedReview is the response returned to /review callers. Just a pointer
// to the Rekor entry.
type SignedReview struct {
	RekorURL string `json:"rekor_url"`
}

// PublishReview builds the in-toto statement, DSSE-signs it, and pushes to Rekor.
func (p *Publisher) PublishReview(ctx context.Context, in *ReviewInput) (*SignedReview, error) {
	diffHash := sha256.Sum256(in.DiffBytes)
	diffHex := hex.EncodeToString(diffHash[:])
	certHash := p.signer.CertSHA256()

	statement := inTotoStatement{
		Type:          inTotoStatementType,
		PredicateType: predicateType,
		Subject: []inTotoSubject{{
			Name:   fmt.Sprintf("%s@%s", in.Repo, in.CurrentTag),
			Digest: map[string]string{"sha256": diffHex},
		}},
		Predicate: reviewPredicate{
			Repo:               in.Repo,
			PrevTag:            in.PrevTag,
			CurrentTag:         in.CurrentTag,
			DiffSHA256:         diffHex,
			DiffBytes:          len(in.DiffBytes),
			ReviewText:         in.Result.Summary,
			Malicious:          in.Result.Malicious,
			MaliciousReasoning: in.Result.MaliciousReasoning,
			Model:              in.Result.Model,
			Truncated:          in.Result.Truncated,
			OmittedFiles:       in.Result.OmittedFiles,
			Timestamp:          time.Now().UTC().Format(time.RFC3339),
			CertSHA256:         hex.EncodeToString(certHash[:]),
		},
	}

	payloadBytes, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	envelope, err := p.signEnvelope(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}

	rekorResp, err := p.pushToRekor(ctx, envelope)
	if err != nil {
		return nil, fmt.Errorf("rekor push failed: %w", err)
	}

	return &SignedReview{
		RekorURL: fmt.Sprintf("%s/api/v1/log/entries/%s", p.rekorURL, rekorResp.UUID),
	}, nil
}

// CertSHA256Hex returns the hex-encoded SHA256 of the leaf cert's DER encoding.
func (p *Publisher) CertSHA256Hex() string {
	h := p.signer.CertSHA256()
	return hex.EncodeToString(h[:])
}

// PublishAttestation publishes the enclave's attestation document to Rekor
// as a separate entry keyed by cert_sha256. Called once per boot; the
// attestation is read from the CVM's public ramdisk (/tinfoil/attestation.json).
// A verifier searching Rekor by subject.digest.sha256 = cert_sha256 finds
// this entry and retrieves the full attestation document.
func (p *Publisher) PublishAttestation(ctx context.Context, attestationJSON []byte) (string, error) {
	certHashHex := p.CertSHA256Hex()

	// Compute .hatt. hash: sha256(format + body), matching verifier.Document.Hash()
	var doc attestationDoc
	if err := json.Unmarshal(attestationJSON, &doc); err != nil {
		return "", fmt.Errorf("parsing attestation document: %w", err)
	}
	docHash := sha256.Sum256([]byte(doc.Format + doc.Body))
	attestationHash := hex.EncodeToString(docHash[:])

	statement := attestationStatement{
		Type:          inTotoStatementType,
		PredicateType: attestationPredicateType,
		Subject: []inTotoSubject{{
			Name:   "enclave-cert",
			Digest: map[string]string{"sha256": certHashHex},
		}},
		Predicate: attestationPredicate{
			CertSHA256:      certHashHex,
			AttestationHash: attestationHash,
			Attestation:     json.RawMessage(attestationJSON),
		},
	}

	payloadBytes, err := json.Marshal(statement)
	if err != nil {
		return "", fmt.Errorf("marshal attestation statement: %w", err)
	}

	envelope, err := p.signEnvelope(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("sign attestation envelope: %w", err)
	}

	rekorResp, err := p.pushToRekor(ctx, envelope)
	if err != nil {
		return "", fmt.Errorf("rekor push failed: %w", err)
	}

	return fmt.Sprintf("%s/api/v1/log/entries/%s", p.rekorURL, rekorResp.UUID), nil
}

// signEnvelope wraps payloadBytes in a DSSE envelope using the standard PAE
// (Pre-Authentication Encoding):
//
//	"DSSEv1" SP <type_len> SP <type> SP <payload_len> SP <payload>
//
// We sign sha256(PAE) with ECDSA-P384.
func (p *Publisher) signEnvelope(payload []byte) (dsseEnvelope, error) {
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d ", len(inTotoPayloadType), inTotoPayloadType, len(payload)))
	pae = append(pae, payload...)
	digest := sha256.Sum256(pae)

	sig, err := p.signer.SignDigest(digest[:])
	if err != nil {
		return dsseEnvelope{}, err
	}

	return dsseEnvelope{
		PayloadType: inTotoPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsseSignature{{
			Sig: base64.StdEncoding.EncodeToString(sig),
		}},
	}, nil
}

type rekorEntryResponse struct {
	UUID     string
	LogIndex int64
}

// pushToRekor submits an intoto v0.0.1 entry to Rekor's POST /api/v1/log/entries.
// The response is keyed by UUID; we pull logIndex out of the entry body.
//
// Why intoto v0.0.1 (not v0.0.2 or dsse v0.0.1):
//   - dsse v0.0.1 never stores the envelope payload, only hashes — so the LLM
//     review text would be unretrievable from the rekor_url.
//   - intoto v0.0.2's openapi `format: byte` round-trip (base64 → []byte →
//     string(bytes)) breaks dsse signature verification with "unable to base64
//     decode payload" — confirmed empirically.
//   - intoto v0.0.1 takes the envelope as a JSON string (no double-decode),
//     ships the pubkey separately at spec.publicKey, and stores the decoded
//     in-toto Statement inline (returned as `attestation.data` on GET) under
//     Rekor's 100 KiB attestation cap.
//
// Wire quirk: the dsse verifier inside intoto v0.0.1 matches signatures to the
// single spec.publicKey by *empty* keyid — any non-empty value silently
// produces "0 of 1 signatures accepted". signEnvelope leaves the field unset.
func (p *Publisher) pushToRekor(ctx context.Context, env dsseEnvelope) (*rekorEntryResponse, error) {
	envBytes, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	entry := map[string]any{
		"kind":       "intoto",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"content": map[string]any{
				"envelope": string(envBytes),
			},
			"publicKey": base64.StdEncoding.EncodeToString(p.signer.PublicKeyPEM()),
		},
	}

	body, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal entry: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.rekorURL+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rekor http %d: %s", resp.StatusCode, string(respBody))
	}

	// Response shape: { "<uuid>": { "logIndex": N, ... } }
	var parsed map[string]struct {
		LogIndex int64 `json:"logIndex"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("parse rekor response: %w", err)
	}
	for uuid, v := range parsed {
		return &rekorEntryResponse{UUID: uuid, LogIndex: v.LogIndex}, nil
	}
	return nil, fmt.Errorf("rekor response had no entries: %s", string(respBody))
}
