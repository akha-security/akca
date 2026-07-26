package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
)

type Step struct {
	ID           string            `json:"id"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body,omitempty"`
	Extract      map[string]string `json:"extract,omitempty"`
	ExpectStatus []int             `json:"expect_status,omitempty"`
	Risk         safemutation.Risk `json:"risk"`
	Cleanup      *Step             `json:"cleanup,omitempty"`
	Snapshot     *Step             `json:"snapshot,omitempty"`
}

type Definition struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Identity string `json:"identity,omitempty"`
	Steps    []Step `json:"steps"`
}

type StepResult struct {
	StepID          string                    `json:"step_id"`
	Request         httpclient.RequestRecord  `json:"request"`
	Response        httpclient.ResponseRecord `json:"response"`
	Extracted       map[string]string         `json:"extracted,omitempty"`
	CleanupOK       bool                      `json:"cleanup_ok"`
	Canary          string                    `json:"canary,omitempty"`
	StateBeforeHash string                    `json:"state_before_hash,omitempty"`
	StateAfterHash  string                    `json:"state_after_hash,omitempty"`
	CleanupError    string                    `json:"cleanup_error,omitempty"`
}

type RunResult struct {
	WorkflowID string            `json:"workflow_id"`
	Variables  map[string]string `json:"variables"`
	Steps      []StepResult      `json:"steps"`
}

type Doer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

type Recorder struct {
	mu         sync.Mutex
	definition Definition
}

func NewRecorder(id, name, identity string) *Recorder {
	return &Recorder{definition: Definition{ID: id, Name: name, Identity: identity}}
}

func (r *Recorder) Record(id string, rr httpclient.RequestResponse, risk safemutation.Risk, cleanup *Step) error {
	if rr.Request.Method == "" || rr.Request.URL == "" || rr.Response.StatusCode == 0 {
		return fmt.Errorf("workflow step requires a real request/response")
	}
	step := Step{
		ID: id, Method: rr.Request.Method, URL: rr.Request.URL, Headers: workflowHeaders(rr.Request.Headers),
		Body: workflowBody(rr.Request.Body, rr.Request.Headers), ExpectStatus: []int{rr.Response.StatusCode}, Risk: risk, Cleanup: cleanup,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.definition.Steps = append(r.definition.Steps, step)
	return nil
}

func workflowHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string)
	for key, value := range headers {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token", "x-akca-sensor-token":
			continue
		}
		out[key] = value
	}
	return out
}

func workflowBody(body string, headers map[string]string) string {
	if body == "" {
		return ""
	}
	contentType := strings.ToLower(headerValue(headers, "content-type"))
	if strings.Contains(contentType, "application/json") || strings.HasPrefix(strings.TrimSpace(body), "{") {
		var value interface{}
		if json.Unmarshal([]byte(body), &value) == nil {
			redactWorkflowJSON(value)
			if encoded, err := json.Marshal(value); err == nil {
				return string(encoded)
			}
		}
	}
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(body); err == nil {
			for key := range values {
				if sensitiveWorkflowField(key) {
					values.Set(key, secretBinding(key))
				}
			}
			encoded := values.Encode()
			encoded = strings.ReplaceAll(encoded, "%7B%7B", "{{")
			encoded = strings.ReplaceAll(encoded, "%7D%7D", "}}")
			return encoded
		}
	}
	// Multipart boundaries and opaque authentication bodies are unsafe to
	// persist because selectively rewriting them can corrupt replay framing.
	if strings.Contains(contentType, "multipart/form-data") && sensitiveBodyMarker(body) {
		return "{{secret_request_body}}"
	}
	return body
}

func redactWorkflowJSON(value interface{}) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			if sensitiveWorkflowField(key) {
				typed[key] = secretBinding(key)
				continue
			}
			redactWorkflowJSON(child)
		}
	case []interface{}:
		for _, child := range typed {
			redactWorkflowJSON(child)
		}
	}
}

func headerValue(headers map[string]string, wanted string) string {
	for key, value := range headers {
		if strings.EqualFold(strings.TrimSpace(key), wanted) {
			return value
		}
	}
	return ""
}

func sensitiveWorkflowField(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.TrimSpace(key)))
	for _, marker := range []string{"password", "passwd", "passphrase", "secret", "accesstoken", "refreshtoken", "idtoken", "apikey", "privatekey"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func sensitiveBodyMarker(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{"password", "passwd", "passphrase", "secret", "access_token", "refresh_token", "api_key"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func secretBinding(key string) string {
	key = regexp.MustCompile(`[^a-zA-Z0-9_]+`).ReplaceAllString(strings.ToLower(key), "_")
	key = strings.Trim(key, "_")
	if key == "" {
		key = "value"
	}
	return "{{secret_" + key + "}}"
}

func (r *Recorder) Definition() Definition {
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, _ := json.Marshal(r.definition)
	var out Definition
	_ = json.Unmarshal(raw, &out)
	return out
}

type Executor struct {
	doer  Doer
	guard *safemutation.Guard
}

func NewExecutor(doer Doer, policy safemutation.Policy) *Executor {
	return &Executor{doer: doer, guard: safemutation.NewGuard(policy)}
}

func (e *Executor) Run(ctx context.Context, definition Definition, initial map[string]string) (result RunResult, runErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result = RunResult{WorkflowID: definition.ID, Variables: cloneMap(initial)}
	type pendingCleanup struct {
		step       Step
		snapshot   Step
		txID       string
		stepID     string
		beforeHash string
	}
	var cleanups []pendingCleanup
	defer func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancelCleanup()
		var failures []string
		for index := len(cleanups) - 1; index >= 0; index-- {
			pending := cleanups[index]
			cleanupOK := true
			cleanupErr := ""
			if hasUnresolvedBinding(pending.step) {
				cleanupOK = false
				cleanupErr = "cleanup has unresolved bindings"
			} else {
				rr, err := e.doer.Do(cleanupCtx, pending.step.Method, pending.step.URL,
					[]byte(pending.step.Body), pending.step.Headers)
				if err != nil || !expectedStatus(rr.Response.StatusCode, pending.step.ExpectStatus) {
					cleanupOK = false
					cleanupErr = fmt.Sprintf("cleanup request failed: %v", err)
				}
			}
			afterHash := ""
			if cleanupOK {
				snapshot := pending.snapshot
				if hasUnresolvedBinding(snapshot) {
					cleanupOK = false
					cleanupErr = "cleanup snapshot has unresolved bindings"
				} else {
					state, err := e.doer.Do(cleanupCtx, snapshot.Method, snapshot.URL,
						[]byte(snapshot.Body), snapshot.Headers)
					afterHash = workflowStateHash(state)
					if err != nil || !expectedStatus(state.Response.StatusCode, snapshot.ExpectStatus) ||
						afterHash != pending.beforeHash {
						cleanupOK = false
						cleanupErr = "cleanup did not restore the before-state snapshot"
					}
				}
			}
			if _, err := e.guard.Finish(pending.txID, afterHash, cleanupOK); err != nil && cleanupErr == "" {
				cleanupErr = err.Error()
			}
			for stepIndex := range result.Steps {
				if result.Steps[stepIndex].StepID == pending.stepID {
					result.Steps[stepIndex].CleanupOK = cleanupOK
					result.Steps[stepIndex].StateAfterHash = afterHash
					result.Steps[stepIndex].CleanupError = cleanupErr
				}
			}
			if !cleanupOK {
				failures = append(failures, pending.stepID+": "+cleanupErr)
			}
		}
		if len(failures) > 0 {
			cleanupFailure := fmt.Errorf("workflow cleanup failed: %s", strings.Join(failures, "; "))
			if runErr == nil {
				runErr = cleanupFailure
			} else {
				runErr = fmt.Errorf("%v; %w", runErr, cleanupFailure)
			}
		}
	}()
	for _, step := range definition.Steps {
		resolved := bindStep(step, result.Variables)
		if unresolvedSecret(resolved) {
			return result, fmt.Errorf("workflow step %s requires explicit secret bindings", resolved.ID)
		}
		beforeHash := ""
		var snapshot Step
		if resolved.Risk != safemutation.ReadOnly {
			if resolved.Snapshot == nil {
				return result, fmt.Errorf("workflow step %s requires a before-state snapshot", resolved.ID)
			}
			snapshot = bindStep(*resolved.Snapshot, result.Variables)
			if !isReadOnlyMethod(snapshot.Method) || hasUnresolvedBinding(snapshot) {
				return result, fmt.Errorf("workflow step %s has an unsafe state snapshot", resolved.ID)
			}
			state, err := e.doer.Do(ctx, snapshot.Method, snapshot.URL, []byte(snapshot.Body), snapshot.Headers)
			if err != nil || !expectedStatus(state.Response.StatusCode, snapshot.ExpectStatus) {
				return result, fmt.Errorf("workflow step %s before-state snapshot failed", resolved.ID)
			}
			beforeHash = workflowStateHash(state)
		}
		tx, err := e.guard.Begin(safemutation.Operation{
			ID: resolved.ID, ResourceID: snapshot.URL, Risk: resolved.Risk,
			CleanupDefined: resolved.Cleanup != nil || resolved.Risk == safemutation.ReadOnly,
		}, beforeHash)
		if err != nil {
			return result, err
		}
		if resolved.Risk != safemutation.ReadOnly {
			if resolved.Headers == nil {
				resolved.Headers = map[string]string{}
			}
			resolved.Headers["X-Akca-Canary"] = tx.Canary
			cleanups = append(cleanups, pendingCleanup{
				step: *resolved.Cleanup, snapshot: snapshot, txID: tx.ID,
				stepID: resolved.ID, beforeHash: beforeHash,
			})
		}
		rr, err := e.doer.Do(ctx, resolved.Method, resolved.URL, []byte(resolved.Body), resolved.Headers)
		if err != nil {
			if resolved.Risk == safemutation.ReadOnly {
				_, _ = e.guard.Finish(tx.ID, "", true)
			}
			return result, err
		}
		if !expectedStatus(rr.Response.StatusCode, resolved.ExpectStatus) {
			if resolved.Risk == safemutation.ReadOnly {
				_, _ = e.guard.Finish(tx.ID, "", true)
			}
			return result, fmt.Errorf("workflow step %s returned status %d", resolved.ID, rr.Response.StatusCode)
		}
		stepResult := StepResult{
			StepID: resolved.ID, Request: rr.Request, Response: rr.Response,
			Extracted: map[string]string{}, Canary: tx.Canary, StateBeforeHash: beforeHash,
		}
		for name, expression := range resolved.Extract {
			value, ok := extractValue(rr.Response.Body, expression)
			if !ok {
				if resolved.Risk == safemutation.ReadOnly {
					_, _ = e.guard.Finish(tx.ID, "", true)
				}
				return result, fmt.Errorf("workflow step %s could not extract %s", resolved.ID, name)
			}
			result.Variables[name] = value
			stepResult.Extracted[name] = value
		}
		if resolved.Cleanup != nil {
			last := len(cleanups) - 1
			cleanups[last].step = bindStep(*resolved.Cleanup, result.Variables)
			cleanups[last].snapshot = bindStep(snapshot, result.Variables)
		}
		stepResult.CleanupOK = resolved.Risk == safemutation.ReadOnly
		result.Steps = append(result.Steps, stepResult)
		if resolved.Risk == safemutation.ReadOnly {
			_, _ = e.guard.Finish(tx.ID, "", true)
		}
	}
	return result, nil
}

func workflowStateHash(rr httpclient.RequestResponse) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s", rr.Response.StatusCode, rr.Response.Body)))
	return hex.EncodeToString(sum[:])
}

func isReadOnlyMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func hasUnresolvedBinding(step Step) bool {
	if strings.Contains(step.URL, "{{") || strings.Contains(step.Body, "{{") {
		return true
	}
	for _, value := range step.Headers {
		if strings.Contains(value, "{{") {
			return true
		}
	}
	return false
}

func unresolvedSecret(step Step) bool {
	if strings.Contains(step.URL, "{{secret_") || strings.Contains(step.Body, "{{secret_") {
		return true
	}
	for _, value := range step.Headers {
		if strings.Contains(value, "{{secret_") {
			return true
		}
	}
	return false
}

func bindStep(step Step, variables map[string]string) Step {
	step.URL = bind(step.URL, variables)
	step.Body = bind(step.Body, variables)
	for key, value := range step.Headers {
		step.Headers[key] = bind(value, variables)
	}
	if step.Cleanup != nil {
		cleanup := bindStep(*step.Cleanup, variables)
		step.Cleanup = &cleanup
	}
	if step.Snapshot != nil {
		snapshot := bindStep(*step.Snapshot, variables)
		step.Snapshot = &snapshot
	}
	return step
}

func bind(value string, variables map[string]string) string {
	for key, replacement := range variables {
		value = strings.ReplaceAll(value, "{{"+key+"}}", replacement)
	}
	return value
}

func extractValue(body, expression string) (string, bool) {
	if strings.HasPrefix(expression, "regex:") {
		re, err := regexp.Compile(strings.TrimPrefix(expression, "regex:"))
		if err != nil {
			return "", false
		}
		match := re.FindStringSubmatch(body)
		if len(match) < 2 {
			return "", false
		}
		return match[1], true
	}
	var value interface{}
	if json.Unmarshal([]byte(body), &value) != nil {
		return "", false
	}
	current := value
	for _, part := range strings.Split(strings.TrimPrefix(expression, "json:"), ".") {
		switch typed := current.(type) {
		case map[string]interface{}:
			current = typed[part]
		case []interface{}:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(typed) {
				return "", false
			}
			current = typed[index]
		default:
			return "", false
		}
	}
	if current == nil {
		return "", false
	}
	return fmt.Sprint(current), true
}

func ExtractValue(body, expression string) (string, bool) {
	return extractValue(body, expression)
}

func expectedStatus(status int, allowed []int) bool {
	if len(allowed) == 0 {
		return status >= 200 && status < 400
	}
	for _, value := range allowed {
		if status == value {
			return true
		}
	}
	return false
}

func cloneMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
