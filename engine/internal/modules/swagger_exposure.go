package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

var swaggerPaths = []struct {
	path        string
	kind        string
	title       string
	fingerprint string
}{
	{"/swagger.json", "swagger_v2_json", "Swagger 2.0 API Specification Exposed", `"swagger":`},
	{"/openapi.json", "openapi_v3_json", "OpenAPI 3.0 API Specification Exposed", `"openapi":`},
	{"/v2/api-docs", "spring_v2_api_docs", "Springfox Swagger v2 API-Docs Exposed", `"swagger":`},
	{"/v3/api-docs", "spring_v3_api_docs", "Springdoc OpenAPI v3 API-Docs Exposed", `"openapi":`},
	{"/api-docs.json", "api_docs_json", "API Documentation Spec Exposed", `"paths":`},
	{"/swagger/v1/swagger.json", "aspnet_swagger_json", "ASP.NET Core Swagger Endpoint Exposed", `"swagger":`},
	{"/docs/openapi.json", "fastapi_openapi_json", "FastAPI OpenAPI Specification Exposed", `"openapi":`},
}

func (r *Runner) runSwaggerExposure(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("swagger_exposure", target); !ok {
		r.emitSkip("swagger_exposure", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host

	// Wildcard / SPA check
	wildcardURL := origin + "/akca-swagger-check-" + randomProbeToken()
	wRR, err := r.client.Do(ctx, "GET", wildcardURL, nil, nil)
	wildcard200 := (err == nil && wRR.Response.StatusCode == 200 && len(wRR.Response.Body) > 100)

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding
	for _, sp := range swaggerPaths {
		if ctx.Err() != nil {
			break
		}
		probeURL := origin + sp.path
		if !r.scope.IsInScope(probeURL) {
			continue
		}

		rr, err := r.client.Do(ctx, "GET", probeURL, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}

		body := strings.TrimSpace(rr.Response.Body)
		if wildcard200 && bodiesSimilar(body, wRR.Response.Body) {
			continue
		}

		// Reject HTML 200 custom 404 pages
		if strings.Contains(body, "<html") || strings.Contains(body, "<!DOCTYPE") {
			continue
		}

		if strings.Contains(body, sp.fingerprint) && strings.Contains(body, `"paths"`) {
			signal := sp.kind
			p := defaultPayload("swagger_exposure", signal, sp.path, signal)
			f := r.verifyAndBuild(ctx, "swagger_exposure", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Severity = "medium"
				f.Title = sp.title
				f.Description = fmt.Sprintf("API documentation specification at '%s' is publicly accessible, disclosing internal endpoints, parameters, and models.", probeURL)
				r.recordFinding(ctx, &out, f, "swagger_exposure", signal)
				return out
			}
		}
	}

	return out
}

func swaggerExposureSignalConfirmed(signal, body string, status int) bool {
	if status != 200 || strings.Contains(body, "<html") || strings.Contains(body, "<!DOCTYPE") {
		return false
	}
	for _, path := range swaggerPaths {
		if path.kind == signal {
			return strings.Contains(body, path.fingerprint) && strings.Contains(body, `"paths"`)
		}
	}
	return false
}
