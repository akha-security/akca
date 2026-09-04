package modules

import (
	"context"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type springProbeDef struct {
	path     string
	kind     string
	title    string
	severity string
	markers  []string
	desc     string
}

var springProbes = []springProbeDef{
	// Spring Cloud Config
	{
		path:     "/application/default",
		kind:     "spring_cloud_config",
		title:    "Spring Cloud Config Server Default Profile Exposed",
		severity: "critical",
		markers:  []string{"propertySources", "name", "profiles"},
		desc:     "Spring Cloud Config Server is exposed, disclosing application configurations, internal endpoints, and credentials.",
	},
	{
		path:     "/application/prod",
		kind:     "spring_cloud_config_prod",
		title:    "Spring Cloud Config Server Production Profile Exposed",
		severity: "critical",
		markers:  []string{"propertySources", "name"},
		desc:     "Spring Cloud Config Server production profile is accessible without authentication.",
	},
	{
		path:     "/application/default/master",
		kind:     "spring_cloud_config_master",
		title:    "Spring Cloud Config Server Master Branch Exposed",
		severity: "critical",
		markers:  []string{"propertySources", "label"},
		desc:     "Spring Cloud Config Server master branch endpoint is accessible without authentication.",
	},
	// Spring Jolokia JMX
	{
		path:     "/jolokia",
		kind:     "spring_jolokia_agent",
		title:    "Spring Jolokia JMX Agent Exposed",
		severity: "high",
		markers:  []string{"agent", "protocol"},
		desc:     "Jolokia JMX HTTP agent is publicly accessible, allowing remote JMX MBean inspection and execution.",
	},
	{
		path:     "/actuator/jolokia",
		kind:     "spring_actuator_jolokia",
		title:    "Spring Boot Actuator Jolokia Agent Exposed",
		severity: "high",
		markers:  []string{"agent", "protocol"},
		desc:     "Jolokia JMX endpoint exposed under Spring Boot Actuator.",
	},
	{
		path:     "/jolokia/list",
		kind:     "spring_jolokia_list",
		title:    "Spring Jolokia MBean Hierarchy Exposed",
		severity: "high",
		markers:  []string{"value", "java.lang"},
		desc:     "Jolokia MBean list endpoint is exposed, disclosing server runtime state and loaded JMX beans.",
	},
	{
		path:     "/actuator/jolokia/list",
		kind:     "spring_actuator_jolokia_list",
		title:    "Spring Boot Actuator Jolokia MBean List Exposed",
		severity: "high",
		markers:  []string{"value", "java.lang"},
		desc:     "Jolokia MBean list endpoint exposed under Spring Boot Actuator.",
	},
}

func (r *Runner) runSpringCloudJolokia(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("spring_cloud_jolokia", target); !ok {
		r.emitSkip("spring_cloud_jolokia", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host

	// Wildcard / SPA check
	wildcardURL := origin + "/akca-spring-check-" + randomProbeToken()
	wRR, err := r.client.Do(ctx, "GET", wildcardURL, nil, nil)
	wildcard200 := (err == nil && wRR.Response.StatusCode == 200 && len(wRR.Response.Body) > 100)

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		baseline = httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	}

	var out []ModuleFinding
	for _, pr := range springProbes {
		if ctx.Err() != nil {
			break
		}
		probeURL := origin + pr.path
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
		if strings.Contains(body, "<html") || strings.Contains(body, "<!DOCTYPE") || strings.Contains(body, "404 Not Found") {
			continue
		}

		allMatched := true
		for _, m := range pr.markers {
			if !strings.Contains(body, m) {
				allMatched = false
				break
			}
		}

		if allMatched {
			p := defaultPayload("spring_cloud_jolokia", pr.kind, pr.path, pr.kind)
			f := r.verifyAndBuild(ctx, "spring_cloud_jolokia", target, p, baseline, rr, pr.kind, false, false, "", "")
			if f != nil {
				f.Severity = pr.severity
				f.Title = pr.title
				f.Description = pr.desc
				r.recordFinding(ctx, &out, f, "spring_cloud_jolokia", pr.kind)
			}
		}
	}

	return out
}

func springCloudJolokiaSignalConfirmed(signal, body string, status int) bool {
	if status != 200 || strings.TrimSpace(body) == "" {
		return false
	}
	for _, probe := range springProbes {
		if probe.kind != signal {
			continue
		}
		for _, marker := range probe.markers {
			if !strings.Contains(body, marker) {
				return false
			}
		}
		return true
	}
	return false
}
