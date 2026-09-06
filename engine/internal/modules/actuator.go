package modules

import (
	"context"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func (r *Runner) runSpringActuator(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("actuator", target); !ok {
		r.emitSkip("actuator", target, reason)
		return nil
	}

	actuatorPaths := []struct {
		path        string
		kind        string
		title       string
		severity    string
		matchMarker string
	}{
		{"/actuator/env", "actuator_env", "Spring Boot Actuator Environment Exposure", "critical", "activeProfiles"},
		{"/env", "actuator_env_legacy", "Spring Boot 1.x Unprefixed Environment Exposure", "critical", "activeProfiles"},
		{"/api/actuator/env", "actuator_env_api", "Spring Boot API Actuator Environment Exposure", "critical", "activeProfiles"},
		{"/management/env", "actuator_env_mgmt", "Spring Boot Management Environment Exposure", "critical", "activeProfiles"},
		{"/actuator/heapdump", "actuator_heapdump", "Spring Boot Memory HeapDump Binary Exposure", "critical", "HPROF"},
		{"/heapdump", "actuator_heapdump_legacy", "Spring Boot 1.x Memory HeapDump Binary Exposure", "critical", "HPROF"},
		{"/actuator/trace", "actuator_trace", "Spring Boot HTTP Trace Leak", "high", "traces"},
		{"/trace", "actuator_trace_legacy", "Spring Boot 1.x HTTP Trace Leak", "high", "traces"},
		{"/actuator/httptrace", "actuator_httptrace", "Spring Boot HTTP Trace Leak", "high", "traces"},
		{"/actuator/mappings", "actuator_mappings", "Spring Boot Mappings Endpoint Exposure", "high", "contexts"},
		{"/mappings", "actuator_mappings_legacy", "Spring Boot 1.x Mappings Endpoint Exposure", "high", "contexts"},
		{"/actuator/configprops", "actuator_configprops", "Spring Boot Config Properties Exposure", "high", "beans"},
		{"/configprops", "actuator_configprops_legacy", "Spring Boot 1.x Config Properties Exposure", "high", "beans"},
		{"/actuator/health", "actuator_health", "Spring Boot Health Endpoint Information", "info", `"status":"UP"`},
		{"/health", "actuator_health_legacy", "Spring Boot 1.x Health Endpoint Information", "info", `"status":"UP"`},
		{"/management/health", "actuator_health_mgmt", "Spring Boot Management Health Endpoint Information", "info", `"status":"UP"`},
		{"/actuator/logfile", "actuator_logfile", "Spring Boot Application Logfile Exposure", "high", "logger"},
		{"/logfile", "actuator_logfile_legacy", "Spring Boot 1.x Application Logfile Exposure", "high", "logger"},
		{"/actuator/gateway/routes", "actuator_gateway_routes", "Spring Cloud Gateway Routes Exposure", "high", "route_id"},
		{"/actuator/prometheus", "actuator_prometheus", "Spring Boot Prometheus Metrics Exposure", "medium", "jvm_memory"},
	}

	var out []ModuleFinding
	originTarget, ok := originScanTarget(target)
	if !ok {
		return nil
	}
	baseline, baselineErr := r.cachedEmptyProbe(ctx, originTarget)
	if baselineErr != nil {
		baseline = httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	}
	base := strings.TrimRight(originTarget.EndpointURL, "/")

	for _, ap := range actuatorPaths {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			return out
		case <-time.After(50 * time.Millisecond):
		}
		targetURL := base + ap.path
		probeTarget := originTarget
		probeTarget.EndpointURL = targetURL
		probeTarget.Parameter = ""
		probeTarget.Location = ""

		rr, err := r.probe(ctx, probeTarget, "")
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}

		// Reject redirects that take us away from the actuator probe path (e.g. 302 to /login or /)
		if rr.Response.Redirected {
			finalClean := strings.TrimRight(rr.Response.FinalURL, "/")
			origClean := strings.TrimRight(targetURL, "/")
			if finalClean != origClean {
				continue
			}
		}

		body := rr.Response.Body
		// Reject HTML web pages unless it's a binary heap dump
		ct := strings.ToLower(rr.Response.Headers["Content-Type"])
		if ap.kind != "actuator_heapdump" && (strings.Contains(ct, "text/html") || strings.Contains(strings.ToLower(body), "<!doctype") || strings.Contains(strings.ToLower(body), "<html")) {
			continue
		}

		isHealthMatch := (strings.Contains(ap.kind, "health") && (strings.Contains(body, `"status":"UP"`) || strings.Contains(body, `"status": "UP"`) || strings.Contains(body, `"status":"DOWN"`) || strings.Contains(body, `"status":"OUT_OF_SERVICE"`)))
		if strings.Contains(body, ap.matchMarker) || isHealthMatch || (ap.kind == "actuator_heapdump" && (strings.HasPrefix(body, "JAVA PROFILE") || strings.Contains(body, "HPROF"))) {
			p := defaultPayload("actuator", ap.kind, ap.path, ap.kind)
			f := r.verifyAndBuild(ctx, "actuator", probeTarget, p, baseline, rr, ap.kind, false, false, "", "")
			if f != nil {
				f.Title = ap.title
				f.Severity = ap.severity
				extractedSecrets := extractActuatorSecrets(body)
				if len(extractedSecrets) > 0 {
					f.Severity = "critical"
					f.Description = "Unauthenticated Spring Boot Actuator endpoint (" + ap.path + ") exposed internal secrets: " + strings.Join(extractedSecrets, ", ")
				} else {
					f.Description = "Unauthenticated Spring Boot Actuator endpoint (" + ap.path + ") was accessed and returned sensitive internal application state."
				}
				r.recordFinding(ctx, &out, f, "actuator", ap.kind)
			}
		}
	}
	return out
}

func extractActuatorSecrets(body string) []string {
	var out []string
	lower := strings.ToLower(body)
	patterns := []struct {
		needle string
		label  string
	}{
		{"spring.datasource.password", "Database Password Property"},
		{"aws_secret_access_key", "AWS Secret Access Key"},
		{"aws_access_key_id", "AWS Access Key ID"},
		{"jwt.secret", "JWT Signing Secret"},
		{"jwt_secret", "JWT Secret"},
		{"postgres://", "PostgreSQL Connection URI"},
		{"mysql://", "MySQL Connection URI"},
		{"mongodb://", "MongoDB Connection URI"},
		{"redis://", "Redis Connection URI"},
		{"apikey", "API Key Reference"},
		{"secret_key", "Secret Key Property"},
	}
	for _, pt := range patterns {
		if strings.Contains(lower, pt.needle) {
			out = append(out, pt.label)
		}
	}
	return out
}

func actuatorSignalConfirmed(signal string, response httpclient.ResponseRecord) bool {
	if response.StatusCode != 200 || !strings.HasPrefix(signal, "actuator_") {
		return false
	}
	body := response.Body
	lowerSignal := strings.ToLower(signal)
	switch {
	case strings.Contains(lowerSignal, "heapdump"):
		return strings.HasPrefix(body, "JAVA PROFILE") || strings.Contains(body, "HPROF")
	case strings.Contains(lowerSignal, "health"):
		return strings.Contains(body, `"status":"UP"`) || strings.Contains(body, `"status": "UP"`) ||
			strings.Contains(body, `"status":"DOWN"`) || strings.Contains(body, `"status":"OUT_OF_SERVICE"`)
	case strings.Contains(lowerSignal, "trace"), strings.Contains(lowerSignal, "httptrace"):
		return strings.Contains(body, "traces")
	case strings.Contains(lowerSignal, "mappings"):
		return strings.Contains(body, "contexts")
	case strings.Contains(lowerSignal, "configprops"):
		return strings.Contains(body, "beans")
	case strings.Contains(lowerSignal, "logfile"):
		return strings.Contains(strings.ToLower(body), "logger")
	case strings.Contains(lowerSignal, "gateway"):
		return strings.Contains(body, "route_id")
	case strings.Contains(lowerSignal, "prometheus"):
		return strings.Contains(body, "jvm_memory")
	default:
		return strings.Contains(body, "activeProfiles")
	}
}
