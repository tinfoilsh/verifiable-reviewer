package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	signer, err := NewSigner(cfg)
	if err != nil {
		log.Fatalf("signer: %v", err)
	}
	fp := signer.KeyFingerprint()
	log.Printf("signer ready: tls_key_fp=%x", fp[:8])

	llm := NewLLMClient(cfg)
	publisher := NewPublisher(signer, cfg.RekorURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/review", requireAPIKey(cfg.ReviewerAPIKey, handleReview(llm, publisher)))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}

// requireAPIKey checks `Authorization: Bearer <key>` against the configured key
// in constant time. 401 on missing/wrong.
func requireAPIKey(want string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// reviewRequest is the wire format on POST /review.
type reviewRequest struct {
	Repo      string `json:"repo"`
	PrevTag   string `json:"prev_tag"`
	LatestTag string `json:"latest_tag"`
	// Diff is the unified diff as a single string. The hash of this exact
	// byte sequence is what ends up in the signed attestation's subject.
	Diff string `json:"diff"`
	// Files mirrors the visibility/llm.py packaging — list of {path, patch}
	// entries the LLM gets. The reviewer uses Files for the prompt and Diff
	// for the subject hash; callers should derive both from the same source.
	Files []File `json:"files"`
}

func handleReview(llm *LLMClient, publisher *Publisher) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "POST only")
			return
		}

		var req reviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
			return
		}
		if req.Repo == "" || req.LatestTag == "" || len(req.Files) == 0 || req.Diff == "" {
			writeError(w, http.StatusBadRequest, "repo, latest_tag, diff, and files are required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()

		rctx := &ReviewContext{Repo: req.Repo, Prev: req.PrevTag, Latest: req.LatestTag}
		result, err := llm.SummarizeDiff(ctx, req.Files, rctx)
		if err != nil {
			log.Printf("review %s %s→%s: llm: %v", req.Repo, req.PrevTag, req.LatestTag, err)
			writeError(w, http.StatusBadGateway, "llm call failed")
			return
		}

		signed, err := publisher.PublishReview(ctx, &ReviewInput{
			Repo:      req.Repo,
			PrevTag:   req.PrevTag,
			LatestTag: req.LatestTag,
			DiffBytes: []byte(req.Diff),
			Result:    result,
		})
		if err != nil {
			// Envelope is signed regardless; rekor publish failure is partial.
			log.Printf("review %s %s→%s: publish: %v", req.Repo, req.PrevTag, req.LatestTag, err)
			if signed == nil {
				writeError(w, http.StatusInternalServerError, "envelope signing failed")
				return
			}
			// Return 202: envelope is valid, log entry is missing.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(signed)
			return
		}

		log.Printf("review %s %s→%s: published log_index=%d", req.Repo, req.PrevTag, req.LatestTag, signed.LogIndex)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signed)
	})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
