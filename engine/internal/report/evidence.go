package report

import (
	"strings"

	"github.com/akha-security/akca/engine/internal/storage"
)

const embeddedEvidenceMarker = "\n\nevidence: "

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
	return out
}
