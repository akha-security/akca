package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

type ObservationRole string

const (
	RoleNativeBaseline        ObservationRole = "native_baseline"
	RoleBaselineReplay        ObservationRole = "baseline_replay"
	RolePositiveProbe         ObservationRole = "positive_probe"
	RolePositiveReplay        ObservationRole = "positive_replay"
	RoleNegativeControl       ObservationRole = "negative_control"
	RoleSyntaxControl         ObservationRole = "syntax_control"
	RoleTrueBranch            ObservationRole = "true_branch"
	RoleFalseBranch           ObservationRole = "false_branch"
	RoleStateBefore           ObservationRole = "state_before"
	RoleStateAfter            ObservationRole = "state_after"
	RoleAnonymousControl      ObservationRole = "anonymous_control"
	RoleAnonymousProbe        ObservationRole = "anonymous_probe"
	RoleExpiredSessionControl ObservationRole = "expired_session_control"
	RoleIdentityA             ObservationRole = "role_a"
	RoleIdentityB             ObservationRole = "role_b"
	RoleOASTCallback          ObservationRole = "oast_callback"
	RoleDOMExecution          ObservationRole = "dom_execution"
	RoleRuntimeTrace          ObservationRole = "runtime_trace"
)

// Observation is an immutable, typed record of one real request/response or
// externally received callback. IDs include the role and attempt so copied
// response values cannot masquerade as independent executions.
type Observation struct {
	ID              string          `json:"id"`
	ScanID          string          `json:"scan_id"`
	Module          string          `json:"module"`
	Endpoint        string          `json:"endpoint"`
	Parameter       string          `json:"parameter,omitempty"`
	Location        string          `json:"location,omitempty"`
	Role            ObservationRole `json:"role"`
	Attempt         int             `json:"attempt"`
	IdentityID      string          `json:"identity_id,omitempty"`
	RequestID       string          `json:"request_id,omitempty"`
	RequestMethod   string          `json:"request_method,omitempty"`
	RequestURL      string          `json:"request_url,omitempty"`
	RequestHash     string          `json:"request_hash,omitempty"`
	ResponseHash    string          `json:"response_hash,omitempty"`
	NormalizedHash  string          `json:"normalized_hash,omitempty"`
	StatusCode      int             `json:"status_code,omitempty"`
	ContentType     string          `json:"content_type,omitempty"`
	DurationMs      int64           `json:"duration_ms,omitempty"`
	StateBeforeHash string          `json:"state_before_hash,omitempty"`
	StateAfterHash  string          `json:"state_after_hash,omitempty"`
	OASTPayloadID   string          `json:"oast_payload_id,omitempty"`
	RuntimeTraceID  string          `json:"runtime_trace_id,omitempty"`
	RuntimeSink     string          `json:"runtime_sink,omitempty"`
	RuntimeSafe     bool            `json:"runtime_safe,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

func NewHTTPObservation(scanID, module, endpoint, parameter, location string, role ObservationRole,
	attempt int, identityID, method, requestURL, requestBody string, requestHeaders map[string]string,
	response ResponseSnapshot) Observation {
	method = strings.ToUpper(strings.TrimSpace(method))
	requestURL = strings.TrimSpace(requestURL)
	reqHash := hashParts(method, requestURL, requestBody, canonicalHeaders(requestHeaders))
	respHash := hashParts(response.Body)
	normHash := hashParts(NormalizeVolatileFields(response.Body))
	id := hashParts(scanID, module, endpoint, parameter, location, string(role),
		intString(attempt), reqHash, respHash)
	return Observation{
		ID: id, ScanID: scanID, Module: module, Endpoint: endpoint, Parameter: parameter,
		Location: location, Role: role, Attempt: attempt, IdentityID: identityID,
		RequestMethod: method, RequestURL: requestURL, RequestHash: reqHash,
		ResponseHash: respHash, NormalizedHash: normHash, StatusCode: response.StatusCode,
		ContentType: response.ContentType, DurationMs: response.DurationMs, CreatedAt: time.Now().UTC(),
	}
}

func NewOASTObservation(scanID, module, endpoint, parameter, location, payloadID, callbackURL string,
	attempt int) Observation {
	id := hashParts(scanID, module, endpoint, parameter, string(RoleOASTCallback), payloadID, callbackURL, intString(attempt))
	return Observation{
		ID: id, ScanID: scanID, Module: module, Endpoint: endpoint, Parameter: parameter,
		Location: location, Role: RoleOASTCallback, Attempt: attempt, OASTPayloadID: payloadID,
		RequestURL: callbackURL, CreatedAt: time.Now().UTC(),
	}
}

func NewRuntimeObservation(scanID, module, endpoint, parameter, location, requestID, traceID, sink string,
	attempt int, safe bool) Observation {
	id := hashParts(scanID, module, endpoint, parameter, string(RoleRuntimeTrace), requestID, traceID, sink, intString(attempt))
	return Observation{
		ID: id, ScanID: scanID, Module: module, Endpoint: endpoint, Parameter: parameter,
		Location: location, Role: RoleRuntimeTrace, Attempt: attempt, RequestID: requestID,
		RuntimeTraceID: traceID, RuntimeSink: sink, RuntimeSafe: safe, CreatedAt: time.Now().UTC(),
	}
}

func (o Observation) Valid() bool {
	if strings.TrimSpace(o.ID) == "" || strings.TrimSpace(o.ScanID) == "" ||
		strings.TrimSpace(o.Module) == "" || strings.TrimSpace(o.Endpoint) == "" ||
		strings.TrimSpace(string(o.Role)) == "" || o.Attempt <= 0 || o.CreatedAt.IsZero() {
		return false
	}
	if o.Role == RoleOASTCallback {
		return strings.TrimSpace(o.OASTPayloadID) != "" && strings.TrimSpace(o.RequestURL) != ""
	}
	if o.Role == RoleRuntimeTrace {
		return strings.TrimSpace(o.RequestID) != "" && strings.TrimSpace(o.RuntimeTraceID) != "" &&
			strings.TrimSpace(o.RuntimeSink) != ""
	}
	return strings.TrimSpace(o.RequestMethod) != "" && strings.TrimSpace(o.RequestURL) != "" &&
		strings.TrimSpace(o.RequestHash) != "" && strings.TrimSpace(o.ResponseHash) != "" &&
		strings.TrimSpace(o.NormalizedHash) != "" && o.StatusCode > 0
}

func ValidateObservations(items []Observation) bool {
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if !item.Valid() {
			return false
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return false
		}
		seen[item.ID] = struct{}{}
	}
	return true
}

func canonicalHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, strings.ToLower(strings.TrimSpace(key)))
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteByte(':')
		for original, value := range headers {
			if strings.EqualFold(strings.TrimSpace(original), key) {
				b.WriteString(value)
				break
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func hashParts(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func intString(v int) string {
	if v == 0 {
		return "0"
	}
	const digits = "0123456789"
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}
