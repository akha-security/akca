package modules

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

// isValidOASTURL rejects malformed callback hosts such as "http://blindxss-cmd./"
// produced when an OAST provider registers without a usable domain.
func isValidOASTURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
	}
	return true
}

func (r *Runner) oastURL(ctx context.Context, payloadID string, target ScanTarget, vulnClass string) string {
	if r.oast == nil {
		return ""
	}
	uniqueID := uniqueOASTPayloadID(payloadID, target, vulnClass)
	var gen oast.GeneratedURL
	var err error
	if bound, ok := r.oast.(interface {
		GenerateBoundURL(oast.ProbeBinding) (oast.GeneratedURL, error)
	}); ok {
		location := strings.TrimSpace(target.Location)
		if location == "" {
			location = "unknown"
		}
		gen, err = bound.GenerateBoundURL(oast.ProbeBinding{
			PayloadID: uniqueID, CandidateID: "candidate-" + uniqueID,
			EndpointURL: target.EndpointURL, Parameter: target.Parameter,
			Location: location, VulnClass: vulnClass,
		})
	} else {
		gen, err = r.oast.GenerateURL(uniqueID, target.EndpointURL, target.Parameter, vulnClass, 0)
	}
	if err != nil {
		return ""
	}
	_ = ctx
	url := strings.TrimSpace(gen.URL)
	if !isValidOASTURL(url) {
		return ""
	}
	return url
}

func uniqueOASTPayloadID(base string, target ScanTarget, vulnClass string) string {
	sum := sha256.Sum256([]byte(target.EndpointURL + "|" + target.Method + "|" + target.Parameter + "|" + target.Location + "|" + vulnClass))
	base = strings.Trim(strings.TrimSpace(base), "-")
	if base == "" {
		base = vulnClass
	}
	return base + "-" + fmt.Sprintf("%x", sum[:6])
}

func (r *Runner) hasOASTCallback(payloadID string) bool {
	if r.db == nil || strings.TrimSpace(payloadID) == "" {
		return false
	}
	ok, err := r.db.HasOASTCallback(r.scanID, payloadID)
	return err == nil && ok
}

// FinalizeOASTFindings materializes confirmed blind/OOB findings only after
// real OAST callbacks were received during the drain phase.
func FinalizeOASTFindings(db *storage.DB, scanID string, emit EventSink) ([]ModuleFinding, error) {
	if db == nil {
		return nil, nil
	}
	records, err := db.ListOASTCallbackRecords(scanID, 500)
	if err != nil {
		return nil, err
	}
	// Prefer HTTP interactions over DNS for the same payload so deduplication
	// retains the stronger fetch evidence.
	sort.SliceStable(records, func(i, j int) bool {
		return oastProtocolStrength(records[i].Protocol) > oastProtocolStrength(records[j].Protocol)
	})
	var out []ModuleFinding
	seen := map[string]struct{}{}
	for _, rec := range records {
		var cb oast.CallbackRecord
		if err := json.Unmarshal([]byte(rec.CallbackJSON), &cb); err != nil {
			continue
		}
		cor := cb.Correlation
		if !validStoredOASTCallback(scanID, rec, cb) {
			continue
		}
		key := cor.VulnClass + "|" + cor.EndpointURL + "|" + cor.Parameter + "|" + rec.PayloadID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if exists, _ := db.HasFindingForOAST(scanID, cor.EndpointURL, cor.VulnClass, rec.PayloadID); exists {
			continue
		}
		f := buildOASTFinding(cor, rec, cb)
		ev, _ := json.Marshal(f.Evidence)
		evJSON := string(ev)
		desc := f.Description + "\n\nevidence: " + evJSON
		conf := confidenceScore(f.Confidence)
		findingID, err := db.SaveFinding(scanID, f.Title, f.Severity, f.VulnClass, desc, f.Endpoint, f.Parameter, conf, evJSON)
		if err != nil {
			continue
		}
		for _, observation := range f.Evidence.Verification.Observations {
			_ = db.SaveVerificationObservation(findingID, storage.VerificationObservationRecord{
				ID: observation.ID, FindingID: findingID, ScanID: observation.ScanID,
				Module: observation.Module, Endpoint: observation.Endpoint, Parameter: observation.Parameter,
				Location: observation.Location, Role: string(observation.Role), Attempt: observation.Attempt,
				RequestURL: observation.RequestURL, OASTPayloadID: observation.OASTPayloadID,
				RuntimeTraceID: observation.RuntimeTraceID, RuntimeSink: observation.RuntimeSink,
				RuntimeSafe: observation.RuntimeSafe,
				CreatedAt:   observation.CreatedAt,
			})
		}
		if emit != nil {
			_ = emit("finding_detected", f.Title, map[string]interface{}{
				"finding_id": findingID,
				"module":     cor.VulnClass, "signal": f.Evidence.Signal,
				"title": f.Title, "severity": strings.ToLower(f.Severity),
				"endpoint": f.Endpoint, "endpoint_url": f.Endpoint,
				"vuln_class": f.VulnClass, "confidence": string(f.Confidence),
				"score": conf, "oast_confirmed": true,
				"method":               f.Evidence.Request.Method,
				"payload_str":          f.Evidence.Payload.Value,
				"parameter":            f.Parameter,
				"location":             f.Location,
				"response_status":      f.Evidence.Response.StatusCode,
				"response_duration_ms": f.Evidence.Response.Duration.Milliseconds(),
				"timing_confirmed":     f.Evidence.Verification.TimingConfirmed,
			})
		}
		out = append(out, f)
	}
	return out, nil
}

func oastProtocolStrength(protocol string) int {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "http", "https":
		return 3
	case "smtp", "ldap":
		return 2
	case "dns":
		return 1
	default:
		return 0
	}
}

func validStoredOASTCallback(scanID string, rec storage.OASTCallbackRecord, cb oast.CallbackRecord) bool {
	cor := cb.Correlation
	if scanID == "" || cb.ScanID != scanID || cor.ScanID != scanID ||
		cb.PayloadID == "" || cb.PayloadID != rec.PayloadID || cor.PayloadID != rec.PayloadID ||
		cor.CandidateID == "" || cor.Nonce == "" || cor.CorrelationToken == "" ||
		cor.EndpointURL == "" || cor.Location == "" || cor.VulnClass == "" ||
		!isValidOASTURL(cor.CallbackURL) {
		return false
	}
	endpoint, err := url.Parse(cor.EndpointURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Hostname() == "" {
		return false
	}
	if cor.RegisteredAt.IsZero() || cb.ReceivedAt.IsZero() || cb.ReceivedAt.Before(cor.RegisteredAt.Add(-time.Minute)) {
		return false
	}
	matched := false
	for _, identifier := range []string{cb.Interaction.UniqueID, cb.Interaction.FullID} {
		identifier = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(identifier, ".")))
		token := strings.ToLower(strings.TrimSpace(cor.CorrelationToken))
		if identifier == token || strings.HasPrefix(identifier, token+".") {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	protocol := strings.ToLower(strings.TrimSpace(cb.Protocol))
	interactionProtocol := strings.ToLower(strings.TrimSpace(cb.Interaction.Protocol))
	storedProtocol := strings.ToLower(strings.TrimSpace(rec.Protocol))
	return protocol != "" && protocol == interactionProtocol && protocol == storedProtocol &&
		cb.Strength == oast.InteractionStrength(protocol)
}

func buildOASTFinding(cor oast.Correlation, rec storage.OASTCallbackRecord, cb oast.CallbackRecord) ModuleFinding {
	module := cor.VulnClass
	signal := oastSignalForModule(module)
	payload := cor.Payload
	if payload == "" {
		payload = cor.CallbackURL
	}
	p := defaultPayload(module, "oast_callback", payload, signal)
	confidence := verification.Confirmed
	score := 0.95
	severity := severityFor(module, confidence)
	descriptionSuffix := ""
	protocol := strings.ToLower(strings.TrimSpace(cb.Protocol))
	if protocol == "dns" {
		confidence = verification.HighConfidence
		score = 0.82
		severity = capSeverity(severityFor(module, confidence), "high")
		descriptionSuffix = " DNS-only callback proves server-side resolution but not an HTTP fetch; impact is therefore downgraded."
	}
	observation := verification.NewOASTObservation(
		cor.ScanID, module, cor.EndpointURL, cor.Parameter, cor.Location,
		cor.PayloadID, cor.CallbackURL, 1,
	)
	return ModuleFinding{
		Title:       findingtext.HumanTitle(module),
		VulnClass:   module,
		Severity:    severity,
		Endpoint:    cor.EndpointURL,
		Parameter:   cor.Parameter,
		Location:    cor.Location,
		Description: findingtext.HumanDescription(module, signal, cor.Parameter, cor.EndpointURL, p.Value, p.Variant, cor.Location) + descriptionSuffix,
		Confidence:  confidence,
		Evidence: Evidence{
			Module: module, Signal: signal, Payload: p,
			Parameter: cor.Parameter, Location: cor.Location,
			OASTURL: cor.CallbackURL,
			Request: cor.Request,
			Verification: verification.Result{
				Confidence:     confidence,
				Score:          score,
				OASTConfirmed:  true,
				ProofType:      verification.ProofOAST,
				ProofPolicy:    verification.CurrentProofPolicyVersion,
				ProofSatisfied: true,
				Observations:   []verification.Observation{observation},
			},
			DetectedAt: cb.ReceivedAt.UTC(),
		},
	}
}

func oastSignalForModule(module string) string {
	switch module {
	case "sqli":
		return "oob_sqli"
	case "lfi":
		return "rfi_oast"
	default:
		return "blind_oast"
	}
}

// sendOASTProbe registers a callback URL and delivers the payload without
// emitting a finding; findings are created later from confirmed callbacks.
func (r *Runner) sendOASTProbe(ctx context.Context, target ScanTarget, payload string) {
	if strings.TrimSpace(payload) == "" || r.oastDeliveryBlocked() {
		return
	}
	rr, err := r.probe(ctx, target, strings.TrimSpace(payload))
	if err != nil {
		// A stopped scan is not an OAST delivery failure and should not leave a
		// scary terminal warning behind while the user is intentionally
		// cancelling the scan.
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		failureClass := oastProbeFailureClass(err)
		if failureClass == "host_circuit_open" {
			r.blockOASTDelivery()
		}
		method := oastProbeMethod(target)
		safeToRetry := oastProbeSafeToRetry(method)
		message := oastProbeFailureMessage(failureClass)
		if failureClass == "connection_closed" && !safeToRetry {
			message += "; automatic retry was skipped because " + method + " may be state-changing"
		}
		r.emitOnce("oast_probe_failed:"+failureClass, "oast_probe_failed", message, map[string]interface{}{
			"endpoint": target.EndpointURL, "parameter": target.Parameter, "method": method,
			"failure_class": failureClass, "failure_scope": "target_delivery",
			"safe_to_retry": safeToRetry, "error": err.Error(),
		})
		return
	}
	if recorder, ok := r.oast.(interface {
		RecordProbe(payload, location string, request httpclient.RequestRecord)
	}); ok {
		recorder.RecordProbe(payload, target.Location, rr.Request)
	}
	_ = r.emit("oast_probe_sent", "blind probe delivered", map[string]interface{}{
		"endpoint": target.EndpointURL, "parameter": target.Parameter, "method": rr.Request.Method,
	})
}

func oastProbeFailureClass(err error) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "connection_closed"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "host circuit open"):
		return "host_circuit_open"
	case strings.Contains(message, "timeout") || strings.Contains(message, "deadline exceeded"):
		return "timeout"
	case strings.Contains(message, "rate limit") || strings.Contains(message, "status 429"):
		return "rate_limited"
	case strings.Contains(message, "unexpected eof") ||
		strings.HasSuffix(strings.TrimSpace(message), ": eof") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "connection closed") ||
		strings.Contains(message, "server closed idle connection"):
		return "connection_closed"
	default:
		return "delivery_error"
	}
}

func oastProbeFailureMessage(failureClass string) string {
	switch failureClass {
	case "connection_closed":
		return "target closed the connection before returning an HTTP response; OAST payload delivery was not confirmed"
	case "timeout":
		return "target did not return an HTTP response before the timeout; OAST payload delivery was not confirmed"
	case "rate_limited":
		return "target rate-limited the probe; OAST payload delivery was not confirmed"
	case "host_circuit_open":
		return "target delivery paused after repeated WAF or rate-limit blocks"
	default:
		return "target request failed before OAST payload delivery could be confirmed"
	}
}

func oastProbeMethod(target ScanTarget) string {
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = http.MethodGet
	}
	location := strings.TrimSpace(target.Location)
	if location == "" {
		location = strings.TrimSpace(target.Profile.ParameterLocation)
	}
	return effectiveMethod(method, location)
}

// OAST probes reuse the endpoint's native method. Retrying a POST/PATCH/PUT
// could duplicate a state-changing action, while GET/HEAD/OPTIONS are safe for
// the HTTP client to retry after a transport-level close.
func oastProbeSafeToRetry(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
