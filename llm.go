package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/tinfoilsh/tinfoil-go"
)

const (
	maxDiffChars    = 80_000
	targetDiffChars = 60_000
	llmRetries      = 2
)

const systemPrompt = `You are reviewing a release diff from a Tinfoil internal repository. Answer two things:

1. malicious: Was anything maliciously added? Look for backdoors, data exfiltration, credential harvesting, obfuscated payloads, suspicious network endpoints, dependency tampering, or hidden network calls. Answer exactly "yes", "no", or "unclear", and include a short explanation in malicious_reasoning.

2. summary: Give a 2-4 sentence plain-English description of what this release changes.

Respond as JSON only, with this exact shape and no other text:
{
  "malicious": "yes|no|unclear",
  "malicious_reasoning": "short explanation",
  "summary": "brief description"
}`

// File is one entry of a packaged diff: a path plus its unified-diff patch.
type File struct {
	Path  string `json:"path"`
	Patch string `json:"patch"`
}

// ReviewContext describes what is being reviewed (used in the LLM prompt header).
type ReviewContext struct {
	Repo    string `json:"repo"`
	Prev    string `json:"prev"`
	Current string `json:"current"`
}

// ReviewResult is the parsed LLM judgment plus packaging metadata.
type ReviewResult struct {
	Malicious          string   `json:"malicious"`
	MaliciousReasoning string   `json:"malicious_reasoning"`
	Summary            string   `json:"summary"`
	Model              string   `json:"model"`
	Truncated          bool     `json:"truncated"`
	OmittedFiles       []string `json:"omitted_files"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// LLMClient wraps a Tinfoil-verified HTTP client
type LLMClient struct {
	httpClient *http.Client
	enclave    string
	apiKey     string
	model      string
}

func NewLLMClient(cfg *Config) (*LLMClient, error) {
	tinfoilClient, err := tinfoil.NewClientWithOptions(
		tinfoil.WithEnclave("inference.tinfoil.sh"),
		tinfoil.WithRepo("tinfoilsh/confidential-model-router"),
		tinfoil.WithTransport(tinfoil.TransportTLS),
	)
	if err != nil {
		return nil, fmt.Errorf("verify inference enclave: %w", err)
	}
	return &LLMClient{
		httpClient: tinfoilClient.HTTPClient(),
		enclave:    tinfoilClient.Enclave(),
		apiKey:     cfg.TinfoilAPIKey,
		model:      cfg.LLMModel,
	}, nil
}

// SummarizeDiff packs files, calls the LLM with retries, and returns a parsed
// result. Returns an error if all retries fail.
func (c *LLMClient) SummarizeDiff(ctx context.Context, files []File, rctx *ReviewContext) (*ReviewResult, error) {
	text, truncated, omitted := packFiles(files)

	var lastErr error
	for attempt := 1; attempt <= llmRetries; attempt++ {
		raw, err := c.callOnce(ctx, text, rctx)
		if err != nil {
			lastErr = err
			continue
		}
		parsed, err := parseJSONObject(raw)
		if err != nil {
			lastErr = err
			continue
		}
		return &ReviewResult{
			Malicious:          stringOr(parsed["malicious"], "unclear"),
			MaliciousReasoning: stringOr(parsed["malicious_reasoning"], ""),
			Summary:            stringOr(parsed["summary"], ""),
			Model:              c.model,
			Truncated:          truncated,
			OmittedFiles:       omitted,
		}, nil
	}
	return nil, fmt.Errorf("llm call failed after %d attempts: %w", llmRetries, lastErr)
}

func (c *LLMClient) callOnce(ctx context.Context, text string, rctx *ReviewContext) (string, error) {
	header := ""
	if rctx != nil {
		if rctx.Repo != "" {
			header += fmt.Sprintf("Repository: %s\n", rctx.Repo)
		}
		if rctx.Prev != "" && rctx.Current != "" {
			header += fmt.Sprintf("Diff: %s → %s\n", rctx.Prev, rctx.Current)
		}
	}
	userMsg := text
	if header != "" {
		userMsg = header + "\n" + text
	}

	body, err := json.Marshal(chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userMsg},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+c.enclave+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm http %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed chatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("unmarshal chat response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	return parsed.Choices[0].Message.Content, nil
}

// packFiles renders all files into a single text payload, smallest-first, up to the budget.
func packFiles(files []File) (text string, truncated bool, omitted []string) {
	type rendered struct {
		path string
		text string
	}
	rs := make([]rendered, 0, len(files))
	total := 0
	for _, f := range files {
		patch := f.Patch
		if patch == "" {
			patch = "(no patch — binary or rename)"
		}
		body := fmt.Sprintf("--- %s ---\n%s", f.Path, patch)
		rs = append(rs, rendered{path: f.Path, text: body})
		total += len(body)
	}

	if total <= maxDiffChars {
		parts := make([]string, len(rs))
		for i, r := range rs {
			parts[i] = r.text
		}
		return strings.Join(parts, "\n\n"), false, nil
	}

	sort.SliceStable(rs, func(i, j int) bool { return len(rs[i].text) < len(rs[j].text) })
	var included []string
	used := 0
	for _, r := range rs {
		if used+len(r.text) <= targetDiffChars {
			included = append(included, r.text)
			used += len(r.text)
		} else {
			omitted = append(omitted, r.path)
		}
	}

	var noteLines []string
	noteLines = append(noteLines, "", fmt.Sprintf("# Truncated: %d large file(s) omitted:", len(omitted)))
	for _, p := range omitted {
		noteLines = append(noteLines, "# - "+p)
	}
	return strings.Join(included, "\n\n") + "\n" + strings.Join(noteLines, "\n"), true, omitted
}

// parseJSONObject decodes a JSON object, falling back to the first
// { … } slice if the LLM wraps it in stray text.
func parseJSONObject(s string) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal([]byte(s), &out); err == nil {
		return out, nil
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start == -1 || end <= start {
		return nil, fmt.Errorf("no JSON object in LLM response")
	}
	if err := json.Unmarshal([]byte(s[start:end+1]), &out); err != nil {
		return nil, fmt.Errorf("parse JSON object: %w", err)
	}
	return out, nil
}

func stringOr(v any, fallback string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fallback
}
