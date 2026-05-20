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
	inTotoStatementType = "https://in-toto.io/Statement/v0.1"
	inTotoPayloadType   = "application/vnd.in-toto+json"
	predicateType       = "https://tinfoil.sh/predicate/code-review/v1"
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

type reviewPredicate struct {
	Repo               string          `json:"repo"`
	PrevTag            string          `json:"prev_tag"`
	LatestTag          string          `json:"latest_tag"`
	DiffSHA256         string          `json:"diff_sha256"`
	Diff               string          `json:"diff"`
	ReviewText         string          `json:"review_text"`
	Malicious          string          `json:"malicious"`
	MaliciousReasoning string          `json:"malicious_reasoning"`
	Model              string          `json:"model"`
	Truncated          bool            `json:"truncated"`
	OmittedFiles       []string        `json:"omitted_files,omitempty"`
	Timestamp          string          `json:"ts"`
	TinfoilAttestation json.RawMessage `json:"tinfoil_attestation"`
}

// dsseEnvelope is the on-the-wire DSSE format (Dead Simple Signing Envelope).
type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"` // base64
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64
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
	Repo      string
	PrevTag   string
	LatestTag string
	DiffBytes []byte
	Result    *ReviewResult
}

// SignedReview is the response returned to /review callers.
type SignedReview struct {
	Envelope dsseEnvelope `json:"envelope"`
	RekorURL string       `json:"rekor_url,omitempty"`
	LogIndex int64        `json:"log_index,omitempty"`
	UUID     string       `json:"uuid,omitempty"`
}

// PublishReview builds the in-toto statement, DSSE-signs it, and pushes to Rekor.
func (p *Publisher) PublishReview(ctx context.Context, in *ReviewInput) (*SignedReview, error) {
	diffHash := sha256.Sum256(in.DiffBytes)
	diffHex := hex.EncodeToString(diffHash[:])

	statement := inTotoStatement{
		Type:          inTotoStatementType,
		PredicateType: predicateType,
		Subject: []inTotoSubject{{
			Name:   fmt.Sprintf("%s@%s", in.Repo, in.LatestTag),
			Digest: map[string]string{"sha256": diffHex},
		}},
		Predicate: reviewPredicate{
			Repo:               in.Repo,
			PrevTag:            in.PrevTag,
			LatestTag:          in.LatestTag,
			DiffSHA256:         diffHex,
			Diff:               string(in.DiffBytes),
			ReviewText:         in.Result.Summary,
			Malicious:          in.Result.Malicious,
			MaliciousReasoning: in.Result.MaliciousReasoning,
			Model:              in.Result.Model,
			Truncated:          in.Result.Truncated,
			OmittedFiles:       in.Result.OmittedFiles,
			Timestamp:          time.Now().UTC().Format(time.RFC3339),
			TinfoilAttestation: p.signer.AttestationDoc(),
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
		// Surface the failure but still return the envelope — callers can
		// retry the push or store the envelope out of band.
		return &SignedReview{Envelope: envelope}, fmt.Errorf("rekor push failed: %w", err)
	}

	return &SignedReview{
		Envelope: envelope,
		RekorURL: fmt.Sprintf("%s/api/v1/log/entries/%s", p.rekorURL, rekorResp.UUID),
		LogIndex: rekorResp.LogIndex,
		UUID:     rekorResp.UUID,
	}, nil
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

	fp := p.signer.KeyFingerprint()
	return dsseEnvelope{
		PayloadType: inTotoPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsseSignature{{
			KeyID: hex.EncodeToString(fp[:]),
			Sig:   base64.StdEncoding.EncodeToString(sig),
		}},
	}, nil
}

type rekorEntryResponse struct {
	UUID     string
	LogIndex int64
}

// pushToRekor submits a DSSE entry to Rekor's POST /api/v1/log/entries.
// The response is keyed by UUID; we pull logIndex out of the entry body.
func (p *Publisher) pushToRekor(ctx context.Context, env dsseEnvelope) (*rekorEntryResponse, error) {
	envBytes, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	// Rekor's DSSE entry kind (v0.0.1) wants the envelope verbatim under spec.envelope
	// plus a list of PEM-encoded verifier public keys/certs under spec.signatures[].publicKey.
	// We don't have a cert to ship (it lives in the embedded attestation_doc), so we
	// supply the bare SPKI as PEM — Rekor accepts either.
	pubPEM, err := p.signer.PublicKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("encode pubkey: %w", err)
	}

	entry := map[string]any{
		"kind":       "dsse",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"proposedContent": map[string]any{
				"envelope": string(envBytes),
				"verifiers": []string{
					base64.StdEncoding.EncodeToString(pubPEM),
				},
			},
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
