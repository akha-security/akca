package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

var oauthAuthPaths = []string{
	"/oauth/authorize",
	"/oauth2/authorize",
	"/oauth/v2/authorize",
	"/oauth2/v1/authorize",
	"/as/authorization.oauth2",
	"/authorize",
	"/login/oauth/authorize",
	"/api/v1/oauth/authorize",
}

func (r *Runner) runOAuthFlow(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("oauth_flow_audit", target); !ok {
		r.emitSkip("oauth_flow_audit", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}

	isOAuthEndpoint := false
	targetPathLower := strings.ToLower(u.Path)
	for _, ap := range oauthAuthPaths {
		if strings.HasSuffix(targetPathLower, ap) || strings.Contains(targetPathLower, "/oauth") {
			isOAuthEndpoint = true
			break
		}
	}
	if !isOAuthEndpoint && u.Query().Get("response_type") == "" && u.Query().Get("client_id") == "" {
		return nil
	}

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding
	// `state` is generated and checked by the relying party, not intrinsically
	// enforceable by an authorization server.  Similarly, accepting a request
	// without PKCE is not proof of a flaw unless the scanner knows the client is
	// public and observes a complete code exchange.  The old mutations therefore
	// produced findings from perfectly valid confidential-client deployments.
	// Keep this module fail-closed and report only a token that the *observed*
	// authorization response places in a URL query string.  Query strings are
	// routinely logged and sent in Referer headers; fragment delivery is the
	// protocol's intentionally different implicit-flow transport and is not
	// enough evidence of a vulnerability by itself.
	if responseTypeRequestsToken(u.Query().Get("response_type")) && oauthTokenInQuery(baseline.Response.Headers) {
		signal := "oauth_token_query_response"
		p := defaultPayload("oauth_flow_audit", signal, "token_in_redirect_query", signal)
		control := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200, Body: "OAuth authorization response without query token"}}
		f := r.verifyAndBuild(ctx, "oauth_flow_audit", target, p, control, baseline, signal, false, false, "", "")
		if f != nil {
			f.Severity = "high"
			f.Title = "OAuth/OIDC token delivered in redirect query string"
			f.Description = fmt.Sprintf("Authorization endpoint '%s' delivered a token in the redirect query string. Query strings are commonly retained in logs, browser history, and Referer headers.", target.EndpointURL)
			r.recordFinding(ctx, &out, f, "oauth_flow_audit", signal)
		}
	}

	return out
}

func responseTypeRequestsToken(responseType string) bool {
	for _, value := range strings.Fields(strings.ToLower(responseType)) {
		if value == "token" || value == "id_token" {
			return true
		}
	}
	return false
}

func oauthTokenInQuery(headers map[string]string) bool {
	location := headerValue(headers, "Location")
	redirect, err := url.Parse(location)
	if err != nil {
		return false
	}
	query := redirect.Query()
	return query.Get("access_token") != "" || query.Get("id_token") != "" || query.Get("token") != ""
}
