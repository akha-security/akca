package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/auth"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/secrets"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

type FindingReplayResult struct {
	FindingID            int64                     `json:"finding_id"`
	Status               string                    `json:"status"`
	OriginalProofType    string                    `json:"original_proof_type,omitempty"`
	StatusCode           int                       `json:"status_code,omitempty"`
	DurationMs           int64                     `json:"duration_ms,omitempty"`
	NormalizedHash       string                    `json:"normalized_hash,omitempty"`
	Reason               string                    `json:"reason,omitempty"`
	OriginalObservations int                       `json:"original_observation_count"`
	Steps                []FindingReplayStepResult `json:"steps,omitempty"`
}

type FindingReplayStepResult struct {
	Role            string `json:"role"`
	IdentityID      string `json:"identity_id,omitempty"`
	StatusCode      int    `json:"status_code,omitempty"`
	DurationMs      int64  `json:"duration_ms,omitempty"`
	NormalizedHash  string `json:"normalized_hash,omitempty"`
	MatchedOriginal bool   `json:"matched_original"`
}

func (e *Engine) ReplayFinding(ctx context.Context, findingID int64) (FindingReplayResult, error) {
	out := FindingReplayResult{FindingID: findingID, Status: "inconclusive"}
	finding, err := e.db.GetFinding(findingID)
	if err != nil {
		return out, err
	}
	scanID, err := e.db.GetFindingScanID(findingID)
	if err != nil {
		return out, err
	}
	var cfg config.ScanConfig
	rawConfig, err := e.db.GetScanConfig(scanID)
	if err != nil || json.Unmarshal([]byte(rawConfig), &cfg) != nil || len(cfg.Targets) == 0 {
		out.Reason = "original scan scope is unavailable"
		return out, nil
	}
	var evidence struct {
		Request    httpclient.RequestRecord `json:"request"`
		ReplayPlan []struct {
			Role                   string                   `json:"role"`
			IdentityID             string                   `json:"identity_id,omitempty"`
			Request                httpclient.RequestRecord `json:"request"`
			ExpectedNormalizedHash string                   `json:"expected_normalized_hash"`
		} `json:"replay_plan,omitempty"`
		Verification struct {
			ProofType string `json:"proof_type"`
		} `json:"verification"`
	}
	rawEvidence := finding.EvidenceJSON
	if rawEvidence == "" {
		rawEvidence = storage.ExtractEmbeddedEvidence(finding.Description)
	}
	if json.Unmarshal([]byte(rawEvidence), &evidence) != nil {
		out.Reason = "replayable request evidence is unavailable"
		return out, nil
	}
	out.OriginalProofType = evidence.Verification.ProofType
	observations, err := e.db.ListVerificationObservations(scanID, findingID, 1000)
	if err != nil {
		return out, err
	}
	out.OriginalObservations = len(observations)
	if len(observations) == 0 {
		out.Reason = "original proof has no typed observations"
		return out, nil
	}
	if len(evidence.ReplayPlan) == 0 {
		if evidence.Request.Method == "" || evidence.Request.URL == "" {
			out.Reason = "replayable request evidence is unavailable"
			return out, nil
		}
		evidence.ReplayPlan = append(evidence.ReplayPlan, struct {
			Role                   string                   `json:"role"`
			IdentityID             string                   `json:"identity_id,omitempty"`
			Request                httpclient.RequestRecord `json:"request"`
			ExpectedNormalizedHash string                   `json:"expected_normalized_hash"`
		}{
			Role: string(verification.RolePositiveProbe), Request: evidence.Request,
			ExpectedNormalizedHash: expectedHashForRole(observations, string(verification.RolePositiveProbe)),
		})
	}
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit))
	if err != nil {
		return out, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	replayCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	safe := map[string]struct{}{}
	for _, item := range observations {
		switch item.Role {
		case string(verification.RoleNativeBaseline), string(verification.RoleBaselineReplay),
			string(verification.RoleNegativeControl), string(verification.RoleSyntaxControl),
			string(verification.RoleStateBefore), string(verification.RoleAnonymousControl):
			safe[item.NormalizedHash] = struct{}{}
		}
	}
	allMatched := true
	fixedSignal := false
	for index, step := range evidence.ReplayPlan {
		method := strings.ToUpper(strings.TrimSpace(step.Request.Method))
		if !safeReplayMethod(method) {
			out.Reason = fmt.Sprintf("replay step %d uses %s and has no recorded cleanup plan", index+1, method)
			return out, nil
		}
		if !scopeEngine.IsInScope(step.Request.URL) {
			out.Reason = fmt.Sprintf("replay step %d is outside the stored scan scope", index+1)
			return out, nil
		}
		headers := cloneReplayHeaders(step.Request.Headers)
		profile, hasProfile, profileErr := replayAuthProfile(
			e.db, cfg, scanID, step.IdentityID, hasRedactedHeader(step.Request.Headers),
		)
		if profileErr != nil {
			out.Reason = profileErr.Error()
			return out, nil
		}
		var rr httpclient.RequestResponse
		if hasProfile {
			rr, err = client.DoWithAuthProfile(replayCtx, method, step.Request.URL,
				[]byte(step.Request.Body), headers, profile)
		} else {
			rr, err = client.Do(replayCtx, method, step.Request.URL, []byte(step.Request.Body), headers)
		}
		if err != nil {
			out.Reason = fmt.Sprintf("replay step %d failed: %v", index+1, err)
			return out, nil
		}
		role := verification.ObservationRole(step.Role)
		if role == "" {
			role = verification.RolePositiveProbe
		}
		replayObservation := verification.NewHTTPObservation(
			scanID, finding.VulnClass, finding.EndpointURL, finding.Parameter, "",
			verification.RolePositiveReplay, index+1, step.IdentityID, method, step.Request.URL,
			step.Request.Body, headers,
			verification.ResponseSnapshot{StatusCode: rr.Response.StatusCode, Body: rr.Response.Body,
				Headers: rr.Response.Headers, DurationMs: rr.Response.Duration.Milliseconds(),
				ContentType: responseContentType(rr.Response.Headers)},
		)
		expected := step.ExpectedNormalizedHash
		if expected == "" {
			expected = expectedHashForRole(observations, string(role))
		}
		matched := expected != "" && replayObservation.NormalizedHash == expected
		allMatched = allMatched && matched
		if isPositiveReplayRole(role) {
			if _, ok := safe[replayObservation.NormalizedHash]; ok {
				fixedSignal = true
			}
		}
		out.StatusCode = rr.Response.StatusCode
		out.DurationMs = rr.Response.Duration.Milliseconds()
		out.NormalizedHash = replayObservation.NormalizedHash
		out.Steps = append(out.Steps, FindingReplayStepResult{
			Role: string(role), IdentityID: step.IdentityID,
			StatusCode: rr.Response.StatusCode, DurationMs: rr.Response.Duration.Milliseconds(),
			NormalizedHash: replayObservation.NormalizedHash, MatchedOriginal: matched,
		})
		_ = e.db.SaveVerificationObservation(findingID, storage.VerificationObservationRecord{
			ID: replayObservation.ID, FindingID: findingID, ScanID: scanID,
			Module: finding.VulnClass, Endpoint: finding.EndpointURL, Parameter: finding.Parameter,
			Role: string(verification.RolePositiveReplay), Attempt: index + 1,
			IdentityID: step.IdentityID, RequestMethod: method, RequestURL: step.Request.URL,
			RequestHash: replayObservation.RequestHash, ResponseHash: replayObservation.ResponseHash,
			NormalizedHash: replayObservation.NormalizedHash, StatusCode: replayObservation.StatusCode,
			ContentType: replayObservation.ContentType, DurationMs: replayObservation.DurationMs,
			CreatedAt: replayObservation.CreatedAt,
		})
	}
	if allMatched {
		out.Status = "still_vulnerable"
		return out, nil
	}
	if fixedSignal {
		out.Status = "fixed"
		return out, nil
	}
	out.Reason = fmt.Sprintf("replayed sequence did not match %d stored proof observations", len(observations))
	return out, nil
}

func safeReplayMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func isPositiveReplayRole(role verification.ObservationRole) bool {
	switch role {
	case verification.RolePositiveProbe, verification.RoleTrueBranch, verification.RoleFalseBranch,
		verification.RoleStateAfter, verification.RoleIdentityB:
		return true
	default:
		return false
	}
}

func expectedHashForRole(items []storage.VerificationObservationRecord, role string) string {
	for _, item := range items {
		if item.Role == role && item.NormalizedHash != "" {
			return item.NormalizedHash
		}
	}
	return ""
}

func hasRedactedHeader(headers map[string]string) bool {
	for _, value := range headers {
		if strings.Contains(value, "[REDACTED]") {
			return true
		}
	}
	return false
}

func cloneReplayHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		if strings.Contains(value, "[REDACTED]") {
			continue
		}
		out[key] = value
	}
	return out
}

func replayAuthProfile(db *storage.DB, cfg config.ScanConfig, scanID, identityID string,
	secretRequired bool) (config.AuthProfile, bool, error) {
	authProfileID := strings.TrimSpace(identityID)
	for _, role := range cfg.RoleProfiles {
		if role.ID == authProfileID {
			authProfileID = role.AuthProfileID
			break
		}
	}
	if authProfileID == "" && secretRequired && len(cfg.AuthProfiles) == 1 {
		authProfileID = cfg.AuthProfiles[0].ID
	}
	if authProfileID == "" {
		if secretRequired {
			return config.AuthProfile{}, false,
				fmt.Errorf("authentication secret is redacted and no exact identity binding is available")
		}
		return config.AuthProfile{}, false, nil
	}
	dataDir, err := storage.DataDir()
	if err != nil {
		return config.AuthProfile{}, false, err
	}
	manager := auth.NewManager(db, secrets.NewStore(string(cfg.CredentialStorageMode), dataDir))
	profile, err := manager.LoadProfile(scanID, authProfileID)
	if err != nil {
		return config.AuthProfile{}, false,
			fmt.Errorf("secure replay identity %q is unavailable: %w", authProfileID, err)
	}
	return profile, true, nil
}

func responseContentType(headers map[string]string) string {
	for key, value := range headers {
		if strings.EqualFold(key, "Content-Type") {
			return value
		}
	}
	return ""
}
