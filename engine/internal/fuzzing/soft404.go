package fuzzing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

type Soft404Profile struct {
	StatusCodes      map[int]int
	BodyHashes       map[string]int
	NormalizedBodies []string
	BodyLengths      []int
}

type Soft404Calibrator struct {
	mu       sync.Mutex
	profiles map[string]*Soft404Profile
}

func NewSoft404Calibrator() *Soft404Calibrator {
	return &Soft404Calibrator{profiles: map[string]*Soft404Profile{}}
}

func (c *Soft404Calibrator) Calibrate(ctx context.Context, client HTTPDoer, baseURL string) {
	host := hostFromURL(baseURL)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomHex := func(n int) string {
		b := make([]byte, n)
		_, _ = rng.Read(b)
		return hex.EncodeToString(b)
	}

	probes := []string{
		"/akca-probe-" + randomHex(8),
		"/akca-probe-" + randomHex(8) + ".html",
		"/api/akca-probe-" + randomHex(8),
	}
	for _, path := range probes {
		if ctx.Err() != nil {
			break
		}
		rr, err := client.Do(ctx, "GET", strings.TrimSuffix(baseURL, "/")+path, nil, nil)
		if err != nil {
			continue
		}
		c.ObserveCalibration(host, rr.Response.StatusCode, rr.Response.Body)
	}
}

// Observe is retained for callers that provide known missing-page samples.
// Runtime fuzz results must never be fed into this method: doing so teaches the
// detector that repeated legitimate pages are soft 404 responses.
func (c *Soft404Calibrator) Observe(host string, status int, body string) {
	c.ObserveCalibration(host, status, body)
}

func (c *Soft404Calibrator) ObserveCalibration(host string, status int, body string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.profiles[host] == nil {
		c.profiles[host] = &Soft404Profile{
			StatusCodes: map[int]int{},
			BodyHashes:  map[string]int{},
		}
	}
	p := c.profiles[host]
	p.StatusCodes[status]++
	h := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(h[:])
	p.BodyHashes[hash]++
	p.NormalizedBodies = append(p.NormalizedBodies, normalizeSoft404Body(body))
	p.BodyLengths = append(p.BodyLengths, len(body))
}

func (c *Soft404Calibrator) IsSoft404(host string, status int, body string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.profiles[host]
	if p == nil {
		return false
	}
	if status == 404 || status == 410 || p.StatusCodes[status] < 2 {
		return false
	}
	h := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(h[:])

	if p.BodyHashes[hash] >= 2 {
		return true
	}

	normalized := normalizeSoft404Body(body)
	matches := 0
	for _, sample := range p.NormalizedBodies {
		if normalized == sample || tokenSimilarity(normalized, sample) >= 0.88 {
			matches++
		}
	}
	return matches >= 2
}

var (
	soft404TagRE       = regexp.MustCompile(`(?s)<[^>]*>`)
	soft404URLPathRE   = regexp.MustCompile(`(?i)(?:https?://[^\s"'<>]+|/[a-z0-9][a-z0-9._~!$&'()*+,;=:@%/\-]*)`)
	soft404ProbeRE     = regexp.MustCompile(`(?i)/?akca-probe-[a-f0-9-]+(?:\.html)?`)
	soft404UUIDRE      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	soft404LongTokenRE = regexp.MustCompile(`(?i)\b[0-9a-f]{12,}\b|\b\d{4,}\b`)
	soft404SpaceRE     = regexp.MustCompile(`\s+`)
)

func normalizeSoft404Body(body string) string {
	body = strings.ToLower(body)
	body = soft404TagRE.ReplaceAllString(body, " ")
	body = soft404ProbeRE.ReplaceAllString(body, " <path> ")
	body = soft404URLPathRE.ReplaceAllString(body, " <path> ")
	body = soft404UUIDRE.ReplaceAllString(body, " <id> ")
	body = soft404LongTokenRE.ReplaceAllString(body, " <id> ")
	return strings.TrimSpace(soft404SpaceRE.ReplaceAllString(body, " "))
}

func tokenSimilarity(left, right string) float64 {
	a := tokenSet(left)
	b := tokenSet(right)
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	intersection := 0
	for token := range a {
		if _, ok := b[token]; ok {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func tokenSet(value string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, token := range strings.Fields(value) {
		out[token] = struct{}{}
	}
	return out
}

func hostFromURL(url string) string {
	u := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	parts := strings.SplitN(u, "/", 2)
	return parts[0]
}

func HostFromURL(url string) string {
	return hostFromURL(url)
}
