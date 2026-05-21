package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxDiffBytes = 10 << 20 // 10 MiB

// GitHubFetcher pulls release diffs from the github.com `.diff` endpoint.
// Anyone with the (repo, prev, current) tuple can re-fetch the exact same
// bytes later, which is what lets a verifier re-derive the subject hash.
type GitHubFetcher struct {
	httpClient *http.Client
}

func NewGitHubFetcher() *GitHubFetcher {
	return &GitHubFetcher{httpClient: &http.Client{Timeout: 60 * time.Second}}
}

// FetchDiff returns the unified diff bytes for repo's prev..current compare URL.
// github.com 302s to codeload.github.com for the body — both must be on the
// shim's egress allowlist.
func (g *GitHubFetcher) FetchDiff(ctx context.Context, repo, prev, current string) ([]byte, error) {
	endpoint := fmt.Sprintf("https://github.com/%s/compare/%s...%s.diff",
		repo, url.PathEscape(prev), url.PathEscape(current))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("github http %d for %s: %s", resp.StatusCode, endpoint, string(body))
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDiffBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read diff: %w", err)
	}
	if len(data) > maxDiffBytes {
		return nil, fmt.Errorf("diff exceeds %d bytes", maxDiffBytes)
	}
	return data, nil
}

// splitUnifiedDiff carves a multi-file unified diff into per-file entries
// for the LLM packer. Each entry's Patch retains the original `diff --git`
// header so the model sees full context.
func splitUnifiedDiff(diff []byte) []File {
	if len(diff) == 0 {
		return nil
	}

	var files []File
	var current *File
	var buf strings.Builder
	flush := func() {
		if current == nil {
			return
		}
		current.Patch = buf.String()
		files = append(files, *current)
	}

	for _, line := range strings.Split(string(diff), "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
			current = &File{Path: extractDiffPath(line)}
			buf.Reset()
		}
		if current != nil {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	flush()
	return files
}

// extractDiffPath pulls the b-side path out of `diff --git a/<P> b/<P>`.
// Uses the first " b/" — fails only on the pathological case of a path
// containing " b/", which we accept.
func extractDiffPath(line string) string {
	i := strings.Index(line, " b/")
	if i < 0 {
		return ""
	}
	return line[i+3:]
}
