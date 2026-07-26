package gitrecover

import (
	"encoding/hex"
	"regexp"
	"strings"
)

// PartialPaths are high-value .git artifacts for partial repository recovery.
var PartialPaths = []string{
	"/.git/HEAD",
	"/.git/config",
	"/.git/index",
	"/.git/logs/HEAD",
	"/.git/logs/refs/heads/master",
	"/.git/logs/refs/heads/main",
	"/.git/refs/heads/master",
	"/.git/refs/heads/main",
	"/.git/packed-refs",
	"/.git/COMMIT_EDITMSG",
	"/.git/description",
	"/.git/info/exclude",
}

var hashRe = regexp.MustCompile(`\b[0-9a-f]{40}\b`)

// RecoveryResult summarizes recoverable git metadata from exposed artifacts.
type RecoveryResult struct {
	BaseURL      string   `json:"base_url"`
	HEADRef      string   `json:"head_ref,omitempty"`
	Branch       string   `json:"branch,omitempty"`
	CommitHashes []string `json:"commit_hashes,omitempty"`
	RemoteURLs   []string `json:"remote_urls,omitempty"`
	IndexPaths   []string `json:"index_paths,omitempty"`
	FetchedPaths []string `json:"fetched_paths,omitempty"`
	ObjectPaths  []string `json:"object_paths,omitempty"`
}

// ParseHEAD extracts ref or detached commit hash from .git/HEAD content.
func ParseHEAD(body string) (ref, hash string) {
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "ref: ") {
		ref = strings.TrimSpace(strings.TrimPrefix(body, "ref: "))
		return ref, ""
	}
	if len(body) == 40 && hashRe.MatchString(body) {
		return "", body
	}
	return "", ""
}

// BranchFromRef returns the short branch name from refs/heads/main style ref.
func BranchFromRef(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	return ref
}

// ParseConfig extracts remote URLs and repository metadata.
func ParseConfig(body string) (remoteURLs []string, repo string) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "url = ") {
			remoteURLs = append(remoteURLs, strings.TrimSpace(line[6:]))
		}
		if strings.HasPrefix(lower, "url=") {
			remoteURLs = append(remoteURLs, strings.TrimSpace(line[4:]))
		}
	}
	return remoteURLs, ""
}

// ExtractCommitHashes finds 40-char git object hashes in log/ref files.
func ExtractCommitHashes(body string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range hashRe.FindAllString(body, -1) {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}

// ObjectStoragePath maps a hash to .git/objects/xx/yyyy path.
func ObjectStoragePath(hash string) string {
	hash = strings.TrimSpace(strings.ToLower(hash))
	if len(hash) < 4 {
		return ""
	}
	return "/.git/objects/" + hash[:2] + "/" + hash[2:]
}

// ExtractIndexPaths heuristically pulls file paths from a binary git index (DIRC).
func ExtractIndexPaths(body []byte) []string {
	if len(body) < 12 || string(body[:4]) != "DIRC" {
		return extractPathsFromText(string(body))
	}
	seen := map[string]struct{}{}
	var out []string
	text := string(body)
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == 0 }) {
		part = strings.TrimSpace(part)
		if !looksLikeProjectPath(part) {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func extractPathsFromText(text string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range pathLikeRe.FindAllString(text, -1) {
		if !looksLikeProjectPath(m) {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}

var pathLikeRe = regexp.MustCompile(`(?:[\w.\-]+/)+[\w.\-]+\.(?:php|py|js|ts|go|rb|java|xml|yml|yaml|env|json|html|css|vue|tsx|jsx|sql|conf|cfg|ini|md)`)

func looksLikeProjectPath(p string) bool {
	if len(p) < 4 || len(p) > 260 {
		return false
	}
	if strings.Contains(p, "..") || strings.HasPrefix(p, "/") {
		return false
	}
	if strings.Count(p, "/") == 0 && !strings.Contains(p, ".") {
		return false
	}
	for _, bad := range []string{"http://", "https://", "DIRC", "refs/", "tree ", "commit "} {
		if strings.Contains(strings.ToLower(p), strings.ToLower(bad)) {
			return false
		}
	}
	return true
}

// IsGitHEAD validates .git/HEAD response body.
func IsGitHEAD(body string) bool {
	body = strings.TrimSpace(body)
	return strings.HasPrefix(body, "ref: refs/") || (len(body) == 40 && hashRe.MatchString(body))
}

// IsGitConfig validates exposed .git/config.
func IsGitConfig(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "[core]") || strings.Contains(lower, "[remote")
}

// IsGitIndex validates DIRC index signature or path-rich fallback.
func IsGitIndex(body []byte) bool {
	if len(body) >= 4 && string(body[:4]) == "DIRC" {
		return true
	}
	return len(ExtractIndexPaths(body)) >= 3
}

// DecodeLooseObject attempts to read plaintext from an uncompressed git loose object body.
func DecodeLooseObject(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	nul := -1
	for i, b := range body {
		if b == 0 {
			nul = i
			break
		}
	}
	if nul >= 0 && nul+1 < len(body) {
		return string(body[nul+1:])
	}
	if isMostlyPrintable(body) {
		return string(body)
	}
	return ""
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 32 && c < 127 || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.85
}

// ValidateObjectHash ensures hash is 40 hex chars.
func ValidateObjectHash(h string) bool {
	if len(h) != 40 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}
