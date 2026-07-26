package reflection

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

type Analyzer struct {
	scanID    string
	client    HTTPDoer
	scope     *scope.Engine
	db        *storage.DB
	emit      EventSink
	maxParams int
	mu        sync.Mutex
}

func NewAnalyzer(scanID string, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, emit EventSink) *Analyzer {
	return &Analyzer{
		scanID: scanID, client: client, scope: scopeEngine, db: db, emit: emit,
		maxParams: 50,
	}
}

func (a *Analyzer) SetMaxParams(n int) {
	if n > 0 {
		a.maxParams = n
	}
}

func (a *Analyzer) Run(ctx context.Context, limit int) ([]ReflectionProfile, error) {
	if limit <= 0 {
		limit = a.maxParams
	}
	_ = a.emit("reflection_started", "reflection analysis started", map[string]interface{}{"scan_id": a.scanID})
	_ = a.db.EnsureScan(a.scanID)

	params, err := a.db.ListParameterTargets(a.scanID, limit)
	if err != nil {
		return nil, err
	}

	var profiles []ReflectionProfile
	for _, target := range params {
		if !a.scope.IsInScope(target.EndpointURL) {
			continue
		}
		profile, err := a.AnalyzeParameter(ctx, target.EndpointURL, target.Method, target.Parameter, target.Location)
		if err != nil {
			continue
		}
		profiles = append(profiles, profile)
		if err := a.db.SaveReflectionProfileContext(ctx, a.scanID, profile); err != nil {
			return nil, fmt.Errorf("save reflection profile for %s (%s): %w",
				profile.EndpointURL, profile.Parameter, err)
		}
		_ = a.emit("reflection_analyzed", profile.Parameter, map[string]interface{}{
			"scan_id": a.scanID, "profile": profile,
		})
	}
	_ = a.emit("reflection_finished", "reflection analysis finished", map[string]interface{}{
		"scan_id": a.scanID, "count": len(profiles),
	})
	return profiles, nil
}

func (a *Analyzer) AnalyzeParameter(ctx context.Context, endpointURL, method, param, location string) (ReflectionProfile, error) {
	method = strings.ToUpper(method)
	if method == "" {
		method = http.MethodGet
	}
	probeMethod := EffectiveMethod(method, location)
	canaryID, canary := NewCanary()
	probeURL, probeBody, probeHeaders, err := BuildProbeRequest(endpointURL, probeMethod, param, location, canary)
	if err != nil {
		return ReflectionProfile{}, err
	}

	rr1, err := a.client.Do(ctx, probeMethod, probeURL, probeBody, probeHeaders)
	if err != nil {
		return ReflectionProfile{}, err
	}
	contentType := headerValue(rr1.Response.Headers, "Content-Type")
	kind := ClassifyReflectionKind(rr1.Response.Body, canary)
	ctxType, quote := ClassifyContext(rr1.Response.Body, canary, contentType)
	avail, blocked := DetectCharAvailability(rr1.Response.Body, canary)

	rr2, err := a.client.Do(ctx, probeMethod, probeURL, probeBody, probeHeaders)
	stable := err == nil &&
		ClassifyReflectionKind(rr2.Response.Body, canary) == kind &&
		func() bool {
			ctx2, _ := ClassifyContext(rr2.Response.Body, canary, contentType)
			return ctx2 == ctxType
		}()

	profile := ReflectionProfile{
		ScanID: a.scanID, EndpointURL: endpointURL, Method: probeMethod,
		Parameter: param, ParameterLocation: location,
		CanaryID: canaryID, CanaryValue: canary,
		ReflectionKind: kind, Context: ctxType, QuoteType: quote,
		AvailableChars: avail, BlockedChars: blocked,
		Stable: stable, ContentType: contentType,
		Confidence: confidenceScore(kind, ctxType, stable),
	}
	profile.HoneypotSuspected = kind == ReflectionRaw && stable && len(blocked) == 0 && len(avail) >= 6
	return profile, nil
}

// buildProbeRequest is a backward-compatible alias for BuildProbeRequest.
func buildProbeRequest(endpointURL, method, param, location, canary string) (string, []byte, map[string]string, error) {
	return BuildProbeRequest(endpointURL, method, param, location, canary)
}

func injectCanary(endpointURL, _ /*method*/, param, _ /*location*/, canary string) (string, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, canary)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func confidenceScore(kind ReflectionKind, ctx ContextType, stable bool) float64 {
	score := 0.4
	if kind == ReflectionRaw || kind == ReflectionEncoded {
		score += 0.25
	}
	if ctx != ContextUnknown {
		score += 0.2
	}
	if stable {
		score += 0.15
	}
	if score > 1 {
		return 1
	}
	return score
}

func headerValue(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func (a *Analyzer) ProbeURL(endpointURL, param, canary string) (string, error) {
	return injectCanary(endpointURL, http.MethodGet, param, "query", canary)
}

func FormatProbe(endpointURL, param, canary string) string {
	u, err := injectCanary(endpointURL, http.MethodGet, param, "query", canary)
	if err != nil {
		return fmt.Sprintf("%s?%s=%s", endpointURL, param, canary)
	}
	return u
}
