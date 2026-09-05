package wafintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/storage"
)

type EventSink func(eventType, message string, payload map[string]interface{}) error

// HTTPDoer performs outbound requests during WAF calibration.
type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (statusCode int, respBody string, err error)
}

type Runner struct {
	scanID string
	db     *storage.DB
	emit   EventSink
	client HTTPDoer
}

type CalibrationOptions struct {
	MaxStrategies int
}

func NewRunner(scanID string, db *storage.DB, emit EventSink) *Runner {
	return &Runner{scanID: scanID, db: db, emit: emit}
}

func (r *Runner) SetClient(client HTTPDoer) {
	r.client = client
}

func (r *Runner) Calibrate(ctx context.Context, targets []string) error {
	return r.CalibrateWithOptions(ctx, targets, CalibrationOptions{MaxStrategies: 3})
}

func (r *Runner) CalibrateWithOptions(ctx context.Context, targets []string, opts CalibrationOptions) error {
	_ = r.emit("waf_evasion_started", "waf evasion intelligence started", map[string]interface{}{"scan_id": r.scanID})
	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		host := HostFromTarget(target)
		if host == "" {
			continue
		}
		waf, err := r.db.GetWAFProfile(r.scanID, host)
		if err != nil || waf.Vendor == "" {
			continue
		}
		learn := r.loadWAFLearn(host)
		probeURL := calibrationURL(target)
		baselineStatus, baselineBody := r.probe(ctx, probeURL, "akca-baseline", nil)

		// Character Pre-flight Matrix: probe critical separator/injection characters
		learn = r.probeCharacterMatrix(ctx, probeURL, baselineStatus, baselineBody, learn)

		strategies := vendorStrategies[strings.ToLower(strings.TrimSpace(waf.Vendor))]
		if len(strategies) == 0 {
			strategies = defaultStrategies()
		}
		limit := len(strategies)
		maxStrategies := opts.MaxStrategies
		if maxStrategies <= 0 {
			maxStrategies = 3
		}
		if limit > maxStrategies {
			limit = maxStrategies
		}
		for i := 0; i < limit; i++ {
			if ctx.Err() != nil {
				break
			}
			strategy := strategies[i]
			sample := `<script>alert(1)</script>`
			mutated, headers := ApplyStrategy(sample, strategy)
			testURL := probeURL
			if strings.Contains(testURL, "?") {
				testURL += "&"
			} else {
				testURL += "?"
			}
			testURL += "akca_waf_probe=" + url.QueryEscape(mutated)
			status, body := r.probe(ctx, testURL, mutated, headers)
			blocked := isWAFBlocked(baselineStatus, baselineBody, status, body)
			learn = RecordStrategyResult(learn, strategy.ID, !blocked)
			for _, enc := range strategy.Encodings {
				learn = RecordTechniqueResult(learn, enc, !blocked)
			}
			for _, protocol := range strategy.Protocol {
				learn = RecordTechniqueResult(learn, "protocol:"+protocol, !blocked)
			}
			raw, _ := json.Marshal(map[string]interface{}{
				"vendor": waf.Vendor, "strategy_id": strategy.ID, "blocked": blocked,
				"status": status, "headers": headers,
			})
			_ = r.db.SaveWAFBypassResult(r.scanID, strategy.ID, string(raw))
		}

		strategy := SelectStrategy(waf.Vendor, learn)
		_, headers := ApplyStrategy(`<script>alert(1)</script>`, strategy)
		result := map[string]interface{}{
			"vendor": waf.Vendor, "strategy_id": strategy.ID, "headers": headers, "verified": r.client != nil,
		}
		raw, _ := json.Marshal(result)
		_ = r.db.SaveWAFBypassResult(r.scanID, strategy.ID, string(raw))
		_ = r.db.SaveWAFLearningProfile(host, learn)
		_ = r.emit("waf_strategy_selected", strategy.Name, map[string]interface{}{
			"scan_id": r.scanID, "host": host, "vendor": waf.Vendor, "strategy_id": strategy.ID,
			"encodings": strategy.Encodings, "protocol": strategy.Protocol,
		})
	}
	_ = r.emit("waf_evasion_finished", "waf evasion intelligence finished", map[string]interface{}{"scan_id": r.scanID})
	return nil
}

func (r *Runner) probe(ctx context.Context, rawURL, payload string, headers map[string]string) (int, string) {
	if r.client == nil {
		return 0, ""
	}
	status, body, err := r.client.Do(ctx, http.MethodGet, rawURL, nil, headers)
	if err != nil {
		return 0, ""
	}
	return status, body
}

// probeCharacterMatrix sends harmless single characters or minimal probes to map
// which syntactic characters trigger WAF blocks and which encodings bypass them.
func (r *Runner) probeCharacterMatrix(ctx context.Context, probeURL string, baseStatus int, baseBody string, learn LearningProfile) LearningProfile {
	if r.client == nil {
		return learn
	}

	charTests := []struct {
		token string
		char  string
	}{
		{"single_quote", "'"},
		{"double_quote", `"`},
		{"angle_bracket", "<"},
		{"semicolon", ";"},
		{"pipe", "|"},
	}

	sep := "?"
	if strings.Contains(probeURL, "?") {
		sep = "&"
	}

	for _, ct := range charTests {
		if ctx.Err() != nil {
			break
		}
		testURL := probeURL + sep + "akca_char_probe=" + url.QueryEscape("akca_"+ct.char)
		status, body := r.probe(ctx, testURL, ct.char, nil)
		blocked := isWAFBlocked(baseStatus, baseBody, status, body)
		learn = RecordCharResult(learn, ct.token, !blocked)

		// If a character was blocked, immediately test if double-url or unicode bypasses it
		if blocked {
			doubleEscaped := url.QueryEscape(url.QueryEscape("akca_" + ct.char))
			statusDbl, bodyDbl := r.probe(ctx, probeURL+sep+"akca_char_probe="+doubleEscaped, ct.char, nil)
			if !isWAFBlocked(baseStatus, baseBody, statusDbl, bodyDbl) {
				learn = RecordTechniqueResult(learn, "double_url", true)
			}
			unicodeEscaped := url.QueryEscape(unicodeEscape(ct.char))
			statusUni, bodyUni := r.probe(ctx, probeURL+sep+"akca_char_probe="+unicodeEscaped, ct.char, nil)
			if !isWAFBlocked(baseStatus, baseBody, statusUni, bodyUni) {
				learn = RecordTechniqueResult(learn, "unicode", true)
			}
		}
	}
	return learn
}

func calibrationURL(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return "https://example.com/"
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func isWAFBlocked(baseStatus int, baseBody string, status int, body string) bool {
	if status == 0 {
		return true
	}
	switch status {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusNotAcceptable, 418:
		return true
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "access denied") || strings.Contains(lower, "request blocked") ||
		strings.Contains(lower, "firewall") || strings.Contains(lower, "captcha") ||
		strings.Contains(lower, "cloudflare") && strings.Contains(lower, "ray id") {
		baseLower := strings.ToLower(baseBody)
		if !strings.Contains(baseLower, "access denied") && !strings.Contains(baseLower, "request blocked") {
			return true
		}
	}
	if baseStatus >= 200 && baseStatus < 400 && status >= 400 && status != http.StatusNotFound {
		return true
	}
	return false
}

func (r *Runner) loadWAFLearn(host string) LearningProfile {
	raw, err := r.db.LoadWAFLearningProfile(host)
	if err != nil {
		return NewLearningProfile(host)
	}
	var lp LearningProfile
	if json.Unmarshal([]byte(raw), &lp) == nil {
		return lp
	}
	return NewLearningProfile(host)
}

func HostFromTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	raw = strings.TrimPrefix(strings.ToLower(raw), "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if idx := strings.Index(raw, "/"); idx >= 0 {
		raw = raw[:idx]
	}
	return raw
}
