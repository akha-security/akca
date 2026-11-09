package report

import (
	"encoding/json"
	"github.com/akha-security/akca/engine/internal/evidencemarkers"
	"strings"
	"unicode/utf8"

	"github.com/akha-security/akca/engine/internal/storage"
)

const embeddedEvidenceMarker = "\n\nevidence: "

const (
	reportRequestEvidenceLimit  = 32 << 10
	reportResponseEvidenceLimit = 96 << 10
)

func stripEmbeddedEvidence(description string) string {
	idx := strings.Index(description, embeddedEvidenceMarker)
	if idx < 0 {
		return strings.TrimSpace(description)
	}
	return strings.TrimSpace(description[:idx])
}

func evidenceJSONFromRecord(rec storage.FindingRecord) string {
	if strings.TrimSpace(rec.EvidenceJSON) != "" {
		return rec.EvidenceJSON
	}
	return storage.ExtractEmbeddedEvidence(rec.Description)
}

func httpEvidenceFromRecord(rec storage.FindingRecord) HTTPEvidence {
	raw := evidenceJSONFromRecord(rec)
	if raw == "" {
		return HTTPEvidence{}
	}
	body := storage.ParseEvidenceBody(raw)
	out := HTTPEvidence{
		Module:           body.Module,
		Signal:           body.Signal,
		Payload:          body.Payload,
		Parameter:        body.Parameter,
		Location:         body.Location,
		ResponseMarkers:  body.ResponseMarkers,
		ProofSummary:     body.ProofSummary,
		Method:           body.Method,
		URL:              body.URL,
		StatusCode:       body.StatusCode,
		DurationMs:       body.DurationMs,
		OASTURL:          body.OASTURL,
		RawRequest:       body.RawRequest,
		RawResponse:      body.RawResponse,
		BodyTruncated:    body.BodyTruncated,
		CurlCommand:      body.CurlCommand,
		RespBody:         body.RespBody,
		ConfidenceScore:  body.ConfidenceScore,
		ProofType:        body.ProofType,
		ProofPolicy:      body.ProofPolicy,
		ProofSatisfied:   body.ProofSatisfied,
		DowngradeReasons: body.DowngradeReasons,
		UpgradeReasons:   body.UpgradeReasons,
		SemanticDelta:    body.SemanticDelta,
		ScreenshotRef:    body.Screenshot,
		DOMSnapshotRef:   body.DOMSnapshot,
	}
	for _, observation := range body.Observations {
		record := storage.VerificationObservationRecord{
			ID: observation.ID, Role: observation.Role, Attempt: observation.Attempt,
			IdentityID: observation.IdentityID, RequestID: observation.RequestID,
			RequestMethod: observation.RequestMethod, RequestURL: observation.RequestURL,
			RequestHash: observation.RequestHash, ResponseHash: observation.ResponseHash,
			NormalizedHash: observation.NormalizedHash, StatusCode: observation.StatusCode,
			DurationMs: observation.DurationMs, StateBeforeHash: observation.StateBeforeHash,
			StateAfterHash: observation.StateAfterHash, OASTPayloadID: observation.OASTPayloadID,
			RuntimeTraceID: observation.RuntimeTraceID,
			RuntimeSink:    observation.RuntimeSink, RuntimeSafe: observation.RuntimeSafe,
		}
		out.Observations = append(out.Observations, record)
		switch observation.Role {
		case "native_baseline", "baseline_replay":
			out.Baseline = append(out.Baseline, record)
		case "positive_probe", "true_branch", "false_branch", "dom_execution":
			out.Probes = append(out.Probes, record)
		case "negative_control", "syntax_control", "anonymous_control", "expired_session_control":
			out.Controls = append(out.Controls, record)
		case "positive_replay":
			out.Replays = append(out.Replays, record)
		case "state_before", "state_after":
			out.State = append(out.State, record)
		case "role_a", "role_b":
			out.Identity = append(out.Identity, record)
		case "oast_callback", "runtime_trace":
			out.ExternalProof = append(out.ExternalProof, record)
		}
	}
	if body.Module == "route_auth_bypass" {
		var extra struct {
			Reference  json.RawMessage `json:"private_resource_reference"`
			ReplayPlan []struct {
				Role    string          `json:"role"`
				Request json.RawMessage `json:"request"`
			} `json:"replay_plan"`
		}
		if json.Unmarshal([]byte(raw), &extra) == nil {
			if len(extra.Reference) > 0 && string(extra.Reference) != "null" {
				referenceJSON, _ := json.Marshal(map[string]json.RawMessage{"response": extra.Reference})
				out.ResourceReference = storage.ParseEvidenceBody(string(referenceJSON)).RawResponse
			}
			for _, step := range extra.ReplayPlan {
				if step.Role != "negative_control" || len(step.Request) == 0 || len(out.ControlRequests) >= 8 {
					continue
				}
				requestJSON, _ := json.Marshal(map[string]json.RawMessage{"request": step.Request})
				out.ControlRequests = append(out.ControlRequests, storage.ParseEvidenceBody(string(requestJSON)).RawRequest)
			}
		}
	}
	return compactHTTPEvidence(out)
}

func compactHTTPEvidence(ev HTTPEvidence) HTTPEvidence {
	if ev.MatchedExcerpt == "" && (len(ev.RawResponse) > reportResponseEvidenceLimit || len(ev.RespBody) > reportResponseEvidenceLimit) {
		body := ev.RespBody
		if len(ev.RawResponse) > len(body) {
			body = ev.RawResponse
		}
		ev.MatchedExcerpt = matchedReportExcerpt(body, evidencemarkers.ForReport(ev.Payload, ev.Signal, body, ev.ResponseMarkers))
	}
	var truncated bool
	ev.RawRequest, truncated = compactReportString(ev.RawRequest, reportRequestEvidenceLimit)
	ev.ReportTruncated = ev.ReportTruncated || truncated
	ev.RawResponse, truncated = compactReportString(ev.RawResponse, reportResponseEvidenceLimit)
	ev.ReportTruncated = ev.ReportTruncated || truncated
	ev.RespBody, truncated = compactReportString(ev.RespBody, reportResponseEvidenceLimit)
	ev.ReportTruncated = ev.ReportTruncated || truncated
	ev.ResourceReference, truncated = compactReportString(ev.ResourceReference, reportResponseEvidenceLimit)
	ev.ReportTruncated = ev.ReportTruncated || truncated
	ev.ControlRequests = append([]string(nil), ev.ControlRequests...)
	for i := range ev.ControlRequests {
		ev.ControlRequests[i], truncated = compactReportString(ev.ControlRequests[i], reportRequestEvidenceLimit)
		ev.ReportTruncated = ev.ReportTruncated || truncated
	}
	return ev
}

// A head/tail excerpt can omit the actual proof in a large response. Preserve
// small windows around exact evidence markers without expanding the full body.
func matchedReportExcerpt(body string, markers []string) string {
	var excerpts []string
	var ranges [][2]int
	for _, marker := range markers {
		if len(marker) < 2 || len(marker) > 512 {
			continue
		}
		index := strings.Index(body, marker)
		if index < 0 {
			continue
		}
		covered := false
		for _, window := range ranges {
			if index >= window[0] && index < window[1] {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		start, end := max(0, index-160), min(len(body), index+len(marker)+160)
		for start > 0 && !utf8.RuneStart(body[start]) {
			start--
		}
		for end < len(body) && !utf8.RuneStart(body[end]) {
			end++
		}
		excerpts = append(excerpts, body[start:end])
		ranges = append(ranges, [2]int{start, end})
		if len(excerpts) == 3 {
			break
		}
	}
	return strings.Join(excerpts, "\n\n…\n\n")
}

// compactReportString keeps both the beginning (status line/headers and common
// proof location) and the tail while the complete transaction remains in the
// local evidence database.
func compactReportString(value string, limit int) (string, bool) {
	if limit <= 0 || len(value) <= limit {
		return value, false
	}
	const marker = "\n...[report excerpt truncated; full value remains in the local database]...\n"
	head := (limit - len(marker)) * 3 / 4
	if head < 0 {
		head = 0
	}
	tail := limit - len(marker) - head
	if tail < 0 {
		tail = 0
	}
	for head > 0 && !utf8.RuneStart(value[head]) {
		head--
	}
	tailStart := len(value) - tail
	for tailStart < len(value) && !utf8.RuneStart(value[tailStart]) {
		tailStart++
	}
	return value[:head] + marker + value[tailStart:], true
}
