package modules

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runOAuth(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("oauth", target); !ok {
		r.emitSkip("oauth", target, reason)
		return nil
	}
	if !isRedirectURIParameter(target.Parameter) {
		return nil
	}
	original := originalOAuthRedirectURI(target)
	if original == "" {
		r.emitSkip("oauth", target, "redirect URI proof requires a recorded native authorization request")
		return nil
	}
	nativeValues := nativeOAuthValues(target)
	nativeState := nativeValues.Get("state")
	if nativeState == "" {
		r.emitSkip("oauth", target, "recorded authorization request has no state binding")
		return nil
	}
	responseType := nativeValues.Get("response_type")
	if strings.Contains(responseType, "id_token") && nativeValues.Get("nonce") == "" {
		r.emitSkip("oauth", target, "OIDC authorization request has no nonce")
		return nil
	}
	if nativeValues.Get("code_challenge") != "" &&
		!strings.EqualFold(nativeValues.Get("code_challenge_method"), "S256") {
		r.emitSkip("oauth", target, "PKCE request does not use S256")
		return nil
	}
	baseline, err := r.probe(ctx, target, original)
	if err != nil {
		return nil
	}
	malicious := "https://akca.invalid/oauth-callback"
	probe, err := r.probe(ctx, target, malicious)
	if err != nil || !oauthRedirectHeaderConfirmed(probe.Response.Headers, malicious) {
		return nil
	}
	if oauthRedirectState(probe.Response.Headers) != nativeState {
		return nil
	}
	control, err := r.probe(ctx, target, "akca-not-a-valid-uri")
	if err != nil || oauthRedirectHeaderConfirmed(control.Response.Headers, "akca-not-a-valid-uri") {
		return nil
	}
	var replays []httpclient.RequestResponse
	for index := 0; index < 2; index++ {
		replay, replayErr := r.probe(ctx, target, malicious)
		if replayErr != nil || !oauthRedirectHeaderConfirmed(replay.Response.Headers, malicious) ||
			oauthRedirectState(replay.Response.Headers) != nativeState {
			return nil
		}
		replays = append(replays, replay)
	}
	payload := defaultPayload("oauth", "redirect_uri_exact_match", malicious, "redirect_uri_location_confirmed")
	finding := r.verifyAndBuildWithCandidate(ctx, "oauth", target, payload, baseline, probe,
		"redirect_uri_location_confirmed", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofDifferentialReplay
			// OAuth redirect proof lives in Location while response bodies are
			// commonly both empty. Body equivalence must not suppress a
			// replayed, state-bound attacker redirect.
			candidate.ExpectedEquivalent = true
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			candidate.TypedReplayHits = []bool{true, true, true}
			candidate.Observations = append(candidate.Observations,
				r.observation("oauth", target, verification.RoleNegativeControl, 1, control),
				r.observation("oauth", target, verification.RolePositiveReplay, 2, replays[0]),
				r.observation("oauth", target, verification.RolePositiveReplay, 3, replays[1]),
			)
		})
	if finding == nil {
		return nil
	}
	finding.Description = "The authorization response sent a code/token to an attacker-controlled exact redirect host; a malformed URI control was not accepted."
	var out []ModuleFinding
	r.recordFinding(&out, finding, "oauth", "redirect_uri_location_confirmed")
	return out
}

func nativeOAuthValues(target ScanTarget) url.Values {
	values := make(url.Values)
	if parsed, err := url.Parse(target.EndpointURL); err == nil {
		for key, items := range parsed.Query() {
			for _, item := range items {
				values.Add(key, item)
			}
		}
	}
	var object map[string]interface{}
	if json.Unmarshal([]byte(target.BodyTemplate), &object) == nil {
		for key, value := range object {
			if text, ok := value.(string); ok {
				values.Set(key, text)
			}
		}
	} else if bodyValues, err := url.ParseQuery(target.BodyTemplate); err == nil {
		for key, items := range bodyValues {
			for _, item := range items {
				values.Add(key, item)
			}
		}
	}
	return values
}

func isRedirectURIParameter(parameter string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(parameter, "-", "_"))
	return normalized == "redirect_uri" || normalized == "redirect_url" ||
		normalized == "callback" || normalized == "return_url"
}

func originalOAuthRedirectURI(target ScanTarget) string {
	parsed, err := url.Parse(target.EndpointURL)
	if err == nil {
		if value := parsed.Query().Get(target.Parameter); value != "" {
			return value
		}
	}
	var object map[string]interface{}
	if json.Unmarshal([]byte(target.BodyTemplate), &object) == nil {
		if value, ok := object[target.Parameter].(string); ok {
			return value
		}
	}
	if values, err := url.ParseQuery(target.BodyTemplate); err == nil {
		return values.Get(target.Parameter)
	}
	return ""
}

func oauthRedirectHeaderConfirmed(headers map[string]string, expected string) bool {
	location := ""
	for key, value := range headers {
		if strings.EqualFold(key, "Location") {
			location = value
			break
		}
	}
	redirect, err := url.Parse(location)
	expectedURL, expectedErr := url.Parse(expected)
	if err != nil || expectedErr != nil || redirect.Hostname() == "" || expectedURL.Hostname() == "" ||
		!strings.EqualFold(redirect.Scheme, expectedURL.Scheme) ||
		!strings.EqualFold(redirect.Host, expectedURL.Host) ||
		redirect.EscapedPath() != expectedURL.EscapedPath() {
		return false
	}
	return oauthValuesContainArtifact(redirect.Query()) || oauthValuesContainArtifact(fragmentValues(redirect.Fragment))
}

func oauthRedirectState(headers map[string]string) string {
	location := headerValue(headers, "Location")
	redirect, err := url.Parse(location)
	if err != nil {
		return ""
	}
	if state := redirect.Query().Get("state"); state != "" {
		return state
	}
	return fragmentValues(redirect.Fragment).Get("state")
}

func oauthValuesContainArtifact(values url.Values) bool {
	return values.Get("code") != "" || values.Get("access_token") != "" || values.Get("id_token") != ""
}

func fragmentValues(fragment string) url.Values {
	values, err := url.ParseQuery(strings.TrimPrefix(fragment, "#"))
	if err != nil {
		return make(url.Values)
	}
	return values
}

func oauthSignal(body, baseline, signal string) bool {
	return signal == "redirect_uri_location_confirmed" && body != baseline
}

func oauthProofSignal(p payloadgen.Payload, baseline, probe httpclient.ResponseRecord) bool {
	return p.ExpectedSignal == "redirect_uri_location_confirmed" &&
		oauthRedirectHeaderConfirmed(probe.Headers, p.Value) &&
		!oauthRedirectHeaderConfirmed(baseline.Headers, p.Value)
}
