package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// TestRekorIntotoSubmit posts a synthetic intoto v0.0.2 entry to real Rekor
// to surface the actual rejection reason, bypassing the redeploy loop.
// Run with: go test -run TestRekorIntotoSubmit -v
func TestRekorIntotoSubmit(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://tinfoil.sh/predicate/code-review/v1",
		"subject": []map[string]any{{
			"name":   "test@v0",
			"digest": map[string]string{"sha256": "deadbeef"},
		}},
		"predicate": map[string]any{
			"repo":        "test",
			"cert_sha256": "00",
			"review_text": "hello",
		},
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}

	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d ", len(inTotoPayloadType), inTotoPayloadType, len(payload)))
	pae = append(pae, payload...)
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	envelope := map[string]any{
		"payloadType": inTotoPayloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]any{{
			"sig": base64.StdEncoding.EncodeToString(sig),
		}},
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	entry := map[string]any{
		"kind":       "intoto",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"content": map[string]any{
				"envelope": string(envelopeJSON),
			},
			"publicKey": base64.StdEncoding.EncodeToString(pubPEM),
		},
	}
	body, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("REQUEST:\n%s", body)

	req, err := http.NewRequest("POST", "https://rekor.sigstore.dev/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	t.Logf("RESPONSE %d:\n%s", resp.StatusCode, respBody)
	if resp.StatusCode >= 400 {
		t.Fatalf("rekor rejected entry: status=%d body=%s", resp.StatusCode, respBody)
	}

	// Pull the entry back and check whether the in-toto Statement is stored inline.
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		t.Fatal(err)
	}
	for uuid := range parsed {
		fetchURL := "https://rekor.sigstore.dev/api/v1/log/entries/" + uuid
		t.Logf("FETCH %s", fetchURL)
		gr, err := http.Get(fetchURL)
		if err != nil {
			t.Fatal(err)
		}
		defer gr.Body.Close()
		got, _ := io.ReadAll(gr.Body)
		t.Logf("RETRIEVED:\n%s", got)
		break
	}
}
