package bypass403

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/akha-security/akca/engine/internal/findingevent"
	"github.com/akha-security/akca/engine/internal/fuzzing"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

type QueueConsumer interface {
	Dequeue() (fuzzing.QueueEntry, bool)
	Metrics() fuzzing.Queue403Metrics
}

type Engine struct {
	scanID  string
	client  HTTPDoer
	scope   *scope.Engine
	db      *storage.DB
	queue   QueueConsumer
	emit    EventSink
	workers int
}

func NewEngine(scanID string, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, queue QueueConsumer, emit EventSink, workers int) *Engine {
	if workers <= 0 {
		workers = 2
	}
	return &Engine{
		scanID: scanID, client: client, scope: scopeEngine, db: db,
		queue: queue, emit: emit, workers: workers,
	}
}

func (e *Engine) Run(ctx context.Context) error {
	_ = e.emit("bypass403_started", "auth bypass checks started", map[string]interface{}{
		"scan_id": e.scanID, "queue": e.queue.Metrics(),
	})
	_ = e.db.EnsureScan(e.scanID)

	entryCh := make(chan fuzzing.QueueEntry, 64)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(entryCh)
		for {
			entry, ok := e.queue.Dequeue()
			if !ok {
				return
			}
			select {
			case <-ctx.Done():
				return
			case entryCh <- entry:
			}
		}
	}()

	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					// Drain remaining entries to unblock producer
					for range entryCh {
					}
					return
				case entry, ok := <-entryCh:
					if !ok {
						return
					}
					e.processEntry(ctx, entry)
				}
			}
		}()
	}
	wg.Wait()

	_ = e.emit("bypass403_finished", "auth bypass checks finished", map[string]interface{}{
		"scan_id": e.scanID, "queue": e.queue.Metrics(),
	})
	return nil
}

func (e *Engine) processEntry(ctx context.Context, entry fuzzing.QueueEntry) {
	if !e.scope.IsInScope(entry.URL) {
		_ = e.emit("scope_blocked", "auth bypass blocked by scope", map[string]interface{}{
			"scan_id": e.scanID, "url": entry.URL, "method": entry.Method,
		})
		return
	}

	baseline, err := e.captureBaseline(ctx, entry.URL, entry.Method)
	if err != nil || !isAuthBlockedStatus(baseline.StatusCode) {
		return
	}
	baselineRecheck, err := e.captureBaseline(ctx, entry.URL, entry.Method)
	if err != nil || !baselinesConsistent(baseline, baselineRecheck) {
		_ = e.emit("auth_baseline_unstable", "unstable access-control baseline suppressed", map[string]interface{}{
			"scan_id": e.scanID, "url": entry.URL, "method": entry.Method,
			"first_status": baseline.StatusCode, "second_status": baselineRecheck.StatusCode,
		})
		return
	}

	_ = e.emit("auth_challenge_analyzed", baseline.AuthScheme.Kind, map[string]interface{}{
		"scan_id": e.scanID, "url": entry.URL, "method": entry.Method,
		"status": baseline.StatusCode, "www_authenticate": baseline.WWWAuthenticate,
		"auth_kind": baseline.AuthScheme.Kind, "has_bearer": baseline.AuthScheme.HasBearer,
		"has_basic": baseline.AuthScheme.HasBasic,
	})

	attempts := BuildAuthBypassAttempts(entry.URL, entry.Method, baseline)
	for _, attempt := range attempts {
		if !e.scope.IsInScope(attempt.URL) {
			continue
		}
		rr, err := e.client.Do(ctx, attempt.Method, attempt.URL, nil, attempt.Headers)
		if err != nil {
			continue
		}

		candidate, reason := IsMeaningfulBypass(baseline, rr.Response.StatusCode, rr.Response.Body)
		result := AttemptResult{
			Attempt: attempt, Baseline: baseline, Request: rr.Request, Response: rr.Response,
			Succeeded: false, Reason: reason,
		}
		if candidate {
			result = e.verifyCandidate(ctx, baseline, attempt, rr, reason)
		}
		succeeded := result.Succeeded
		reason = result.Reason

		_ = e.db.SaveBypassResult(e.scanID, string(attempt.Category), result)
		eventType := "four_oh_three_bypass_attempted"
		if baseline.StatusCode == http.StatusUnauthorized {
			eventType = "four_oh_one_bypass_attempted"
		}
		_ = e.emit(eventType, attempt.Label, map[string]interface{}{
			"scan_id": e.scanID, "url": attempt.URL, "method": attempt.Method,
			"category": attempt.Category, "label": attempt.Label, "status": rr.Response.StatusCode,
			"baseline_status": baseline.StatusCode, "succeeded": succeeded, "reason": reason,
		})

		if succeeded {
			successEvent := "four_oh_three_bypass_succeeded"
			if baseline.StatusCode == http.StatusUnauthorized {
				successEvent = "four_oh_one_bypass_succeeded"
			}
			_ = e.emit(successEvent, attempt.Label, map[string]interface{}{
				"scan_id": e.scanID, "url": attempt.URL, "method": attempt.Method,
				"category": attempt.Category, "baseline_status": baseline.StatusCode,
				"status": rr.Response.StatusCode, "reason": reason,
			})
			_ = e.createFinding(result)
		}
	}
}

func isAuthBlockedStatus(code int) bool {
	return code == http.StatusForbidden || code == http.StatusUnauthorized
}

func (e *Engine) captureBaseline(ctx context.Context, rawURL, method string) (Baseline, error) {
	rr, err := e.client.Do(ctx, method, rawURL, nil, nil)
	if err != nil {
		return Baseline{}, err
	}
	wwwAuth := headerValue(rr.Response.Headers, "WWW-Authenticate")
	return Baseline{
		URL: rawURL, Method: method, StatusCode: rr.Response.StatusCode,
		Body: rr.Response.Body, BodyLength: len(rr.Response.Body),
		WWWAuthenticate: wwwAuth, AuthScheme: ParseWWWAuthenticate(wwwAuth),
		ResponseHeaders: cloneHeaders(rr.Response.Headers),
	}, nil
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func cloneHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (e *Engine) createFinding(result AttemptResult) error {
	statusLabel := "403"
	class := "access_control_bypass"
	if result.Baseline.StatusCode == http.StatusUnauthorized {
		statusLabel = "401"
		class = "auth_bypass"
	}
	title := fmt.Sprintf("%s Bypass via %s (%s)", statusLabel, result.Attempt.Category, result.Attempt.Label)
	desc := fmt.Sprintf(
		"Protected endpoint %s responded with %s baseline (auth: %s) but technique %s (%s) produced status %d: %s",
		result.Baseline.URL, statusLabel, result.Baseline.AuthScheme.Kind,
		result.Attempt.Category, result.Attempt.Label,
		result.Response.StatusCode, result.Reason,
	)
	severity := "High"
	if result.Attempt.Category == JWTBearerAbuse || result.Attempt.Category == BasicAuthAbuse {
		severity = "Critical"
	}
	evidence, _ := json.Marshal(map[string]interface{}{
		"module":                  class,
		"signal":                  string(result.Attempt.Category),
		"payload":                 map[string]string{"value": result.Attempt.Label},
		"location":                "access_control",
		"attempt":                 result.Attempt,
		"baseline":                result.Baseline,
		"request":                 result.Request,
		"response":                result.Response,
		"negative_control":        result.ControlAttempt,
		"control_request":         result.ControlRequest,
		"control_response":        result.ControlResponse,
		"public_control_request":  result.PublicControlRequest,
		"public_control_response": result.PublicControlResponse,
		"recheck_request":         result.RecheckRequest,
		"recheck_response":        result.RecheckResponse,
		"succeeded":               result.Succeeded,
		"reason":                  result.Reason,
	})
	findingID, err := e.db.SaveFinding(e.scanID, title, severity, class, desc, result.Baseline.URL, "", 0.98, string(evidence))
	if err != nil {
		return err
	}
	method := result.Request.Method
	if strings.TrimSpace(method) == "" {
		method = result.Attempt.Method
	}
	_ = e.emit("finding_detected", title, findingevent.Payload(findingevent.Data{
		FindingID: findingID, ScanID: e.scanID, Title: title, Severity: severity,
		VulnClass: class, Endpoint: result.Baseline.URL, Location: "access_control",
		Method: method, Payload: result.Attempt.Label, Signal: string(result.Attempt.Category),
		Score: 0.98, ResponseStatus: result.Response.StatusCode,
		ResponseDuration: result.Response.Duration,
	}))
	return e.db.SaveEvidenceForFinding(e.scanID, findingID, statusLabel+"_bypass", string(evidence))
}
