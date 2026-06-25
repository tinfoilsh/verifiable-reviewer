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

	llm, err := NewLLMClient(cfg)
	if err != nil {
		log.Fatalf("llm: %v", err)
	}
	publisher := NewPublisher(signer, cfg.RekorURL)
	gh := NewGitHubFetcher()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/review", requireAPIKey(cfg.ReviewerAPIKey, handleReview(gh, llm, publisher)))

	const listenAddr = ":8080"
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s", listenAddr)
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

// reviewRequest is the wire format on POST /review. The diff is fetched
// inside the enclave from github.com/<repo>/compare/<prev>...<latest>.diff,
// so the subject hash is over bytes the TEE pulled itself — not bytes a
// caller could have substituted.
type reviewRequest struct {
	Repo      string `json:"repo"`
	PrevTag   string `json:"prev_tag"`
	CurrentTag string `json:"current_tag"`
}

func handleReview(gh *GitHubFetcher, llm *LLMClient, publisher *Publisher) http.Handler {
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
		if req.Repo == "" || req.PrevTag == "" || req.CurrentTag == "" {
			writeError(w, http.StatusBadRequest, "repo, prev_tag, and current_tag are required")
			return
		}

		// 15-min hard cap. Visibility times out its own HTTP request at 5 min
		// and switches to polling Rekor by hash, so any value > 5 min lets
		// the reviewer keep grinding past the client deadline. 15 min covers
		// almost any plausible LLM-slowness scenario before we give up.
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()

		diffBytes, err := gh.FetchDiff(ctx, req.Repo, req.PrevTag, req.CurrentTag)
		if err != nil {
			log.Printf("review %s %s→%s: fetch: %v", req.Repo, req.PrevTag, req.CurrentTag, err)
			writeError(w, http.StatusBadGateway, "diff fetch failed")
			return
		}
		files := splitUnifiedDiff(diffBytes)
		if len(files) == 0 {
			writeError(w, http.StatusUnprocessableEntity, "diff contained no file changes")
			return
		}

		rctx := &ReviewContext{Repo: req.Repo, Prev: req.PrevTag, Current: req.CurrentTag}
		result, err := llm.SummarizeDiff(ctx, files, rctx)
		if err != nil {
			log.Printf("review %s %s→%s: llm: %v", req.Repo, req.PrevTag, req.CurrentTag, err)
			writeError(w, http.StatusBadGateway, "llm call failed")
			return
		}

		signed, err := publisher.PublishReview(ctx, &ReviewInput{
			Repo:      req.Repo,
			PrevTag:   req.PrevTag,
			CurrentTag: req.CurrentTag,
			DiffBytes: diffBytes,
			Result:    result,
		})
		if err != nil {
			log.Printf("review %s %s→%s: publish: %v", req.Repo, req.PrevTag, req.CurrentTag, err)
			writeError(w, http.StatusBadGateway, "rekor publish failed")
			return
		}

		log.Printf("review %s %s→%s: %s", req.Repo, req.PrevTag, req.CurrentTag, signed.RekorURL)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signed)
	})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
