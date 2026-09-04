package casesense

import (
	"context"
	"net/url"
	"strings"
	"unicode"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type Mode int

const (
	Unknown Mode = iota
	CaseSensitive
	CaseInsensitive
)

func (m Mode) String() string {
	switch m {
	case CaseSensitive:
		return "case_sensitive"
	case CaseInsensitive:
		return "case_insensitive"
	default:
		return "unknown"
	}
}

type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

type Detector struct {
	client HTTPDoer
}

func NewDetector(client HTTPDoer) *Detector {
	return &Detector{client: client}
}

// Detect checks if the remote server is case-sensitive or case-insensitive
// by testing an existing valid URL against its case-inverted variant.
func (d *Detector) Detect(ctx context.Context, validURL string, origStatus int, origBody string) (Mode, error) {
	u, err := url.Parse(validURL)
	if err != nil {
		return Unknown, err
	}

	invertedPath := FlipCase(u.Path)
	if invertedPath == u.Path {
		return Unknown, nil
	}

	uInverted := *u
	uInverted.Path = invertedPath
	testURL := uInverted.String()

	rr, err := d.client.Do(ctx, "GET", testURL, nil, nil)
	if err != nil {
		return Unknown, err
	}

	// If the case-inverted path returns the same status code and similar content,
	// the server is case-insensitive (e.g. Windows/IIS).
	if rr.Response.StatusCode == origStatus && (origStatus == 200 || origStatus == 301 || origStatus == 302) {
		if bodiesMatch(origBody, rr.Response.Body) {
			return CaseInsensitive, nil
		}
	}

	// If status codes differ (e.g. 200 vs 404), the server is case-sensitive (e.g. Linux/Nginx).
	return CaseSensitive, nil
}

func FlipCase(path string) string {
	var sb strings.Builder
	hasLetter := false
	for _, r := range path {
		if unicode.IsLetter(r) {
			hasLetter = true
			if unicode.IsUpper(r) {
				sb.WriteRune(unicode.ToLower(r))
			} else {
				sb.WriteRune(unicode.ToUpper(r))
			}
		} else {
			sb.WriteRune(r)
		}
	}
	if !hasLetter {
		return path
	}
	return sb.String()
}

func bodiesMatch(a, b string) bool {
	if a == b {
		return true
	}
	lenDiff := len(a) - len(b)
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}
	if len(a) > 0 && float64(lenDiff)/float64(len(a)) < 0.15 {
		return true
	}
	return false
}
