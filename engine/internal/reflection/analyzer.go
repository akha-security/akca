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
		maxParams: 0,
	}
}

func (a *Analyzer) SetMaxParams(n int) {
	a.maxParams = n
}

func (a *Analyzer) Run(ctx context.Context, limit int) ([]ReflectionProfile, error) {
	if limit == 0 && a.maxParams > 0 {
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
		profile, err := a.AnalyzeParameterWithTemplate(ctx, RequestTemplate{
			Method: target.Method, URL: target.EndpointURL, Headers: target.Headers,
			Body: target.BodyTemplate, ContentType: target.ContentType,
		}, target.Parameter, target.Location)
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
	return a.AnalyzeParameterWithTemplate(ctx, RequestTemplate{Method: method, URL: endpointURL}, param, location)
}

// AnalyzeParameterWithTemplate performs reflection analysis by replaying the
// discovered request rather than synthesizing a new minimal request.
func (a *Analyzer) AnalyzeParameterWithTemplate(ctx context.Context, template RequestTemplate, param, location string) (ReflectionProfile, error) {
	canaryID, canary := NewCanary()
	probe, err := MutateRequest(template, param, location, canary)
	if err != nil {
		return ReflectionProfile{}, err
	}

	rr1, err := a.client.Do(ctx, probe.Method, probe.URL, probe.Body, probe.Headers)
	if err != nil {
		return ReflectionProfile{}, err
	}
	responseContentType := headerValue(rr1.Response.Headers, "Content-Type")
	requestContentType := template.ContentType
	if requestContentType == "" {
		requestContentType = headerValue(template.Headers, "Content-Type")
	}
	contentType := requestContentType
	if contentType == "" {
		contentType = responseContentType
	}
	kind := ClassifyReflectionKind(rr1.Response.Body, canary)
	ctxType, quote := ClassifyContext(rr1.Response.Body, canary, responseContentType)
	avail, blocked := DetectCharAvailability(rr1.Response.Body, canary)

	// If reflection is observed, perform a dedicated sentinel probe to genuinely test
	// which special characters the target server allows, encodes, or filters.
	if kind == ReflectionRaw || kind == ReflectionEncoded || kind == ReflectionPartial {
		charCanary := buildCharSentinelPayload(canary)
		if probe3, err3 := MutateRequest(template, param, location, charCanary); err3 == nil {
			if rr3, err3 := a.client.Do(ctx, probe3.Method, probe3.URL, probe3.Body, probe3.Headers); err3 == nil {
				activeAvail, activeBlocked, hasEncoded := evaluateCharSentinels(rr3.Response.Body)
				if len(activeAvail) > 0 || len(activeBlocked) > 0 {
					avail = activeAvail
					blocked = activeBlocked
					if hasEncoded && kind != ReflectionRaw {
						kind = ReflectionEncoded
					}
				}
			}
		}
	}

	rr2, err := a.client.Do(ctx, probe.Method, probe.URL, probe.Body, probe.Headers)
	stable := err == nil &&
		ClassifyReflectionKind(rr2.Response.Body, canary) == kind &&
		func() bool {
			ctx2, _ := ClassifyContext(rr2.Response.Body, canary, responseContentType)
			return ctx2 == ctxType
		}()

	profile := ReflectionProfile{
		ScanID: a.scanID, EndpointURL: template.URL, Method: probe.Method,
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

var sentinelProbes = []struct {
	char            string
	rawPattern      string
	encodedPatterns []string
}{
	{"<", "AK<BK", []string{"AK&lt;BK", "AK&#60;BK", "AK&#x3c;BK", "AK%3CBK", "AK%3cbk"}},
	{">", "CK>DK", []string{"CK&gt;DK", "CK&#62;DK", "CK&#x3e;DK", "CK%3EBK", "CK%3ebk"}},
	{"\"", "EK\"FK", []string{"EK&quot;FK", "EK&#34;FK", "EK&#x22;FK", "EK%22FK", "EK\\\"FK"}},
	{"'", "GK'HK", []string{"GK&#39;HK", "GK&#x27;HK", "GK&apos;HK", "GK%27HK", "GK\\'HK"}},
	{"`", "IK`JK", []string{"IK&#96;JK", "IK&#x60;JK", "IK%60JK", "IK\\`JK"}},
	{"(", "KK(LK", []string{"KK&#40;LK", "KK%28LK"}},
	{")", "MK)NK", []string{"MK&#41;NK", "MK%29NK"}},
	{"{", "OK{PK", []string{"OK&#123;PK", "OK%7BPK"}},
	{"}", "QK}RK", []string{"QK&#125;RK", "QK%7DPK"}},
	{"/", "SK/TK", []string{"SK&#47;TK", "SK%2FTK"}},
	{"\\", "UK\\VK", []string{"UK&#92;VK", "UK%5CVK"}},
	{"&", "WK&XK", []string{"WK&amp;XK", "WK&#38;XK", "WK%26XK"}},
	{";", "YK;ZK", []string{"YK&#59;ZK", "YK%3BZK"}},
}

func buildCharSentinelPayload(canary string) string {
	return canary + "AK<BK>CK\"DK'EK`FK(GK)HK{IK}JK/KK\\LK&MK;NK" + canary
}

func evaluateCharSentinels(body string) (available, blocked []string, hasEncoded bool) {
	for _, s := range sentinelProbes {
		if strings.Contains(body, s.rawPattern) {
			available = append(available, s.char)
			continue
		}
		isEnc := false
		for _, enc := range s.encodedPatterns {
			if strings.Contains(body, enc) {
				isEnc = true
				hasEncoded = true
				break
			}
		}
		blocked = append(blocked, s.char)
		_ = isEnc
	}
	return available, blocked, hasEncoded
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
