package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type cloudNativeProbe struct {
	path        string
	signal      string
	title       string
	severity    string
	description string
	check       func(status int, body string) bool
}

var cloudNativeProbes = []cloudNativeProbe{
	// 1. Docker Daemon API Exposure
	{
		path:        "/v1.24/containers/json",
		signal:      "docker_daemon_api_exposed",
		title:       "Docker Daemon API Unauthenticated Exposure",
		severity:    "critical",
		description: "Unauthenticated Docker Engine HTTP API was accessible, allowing arbitrary container creation, execution, and host system compromise.",
		check: func(status int, body string) bool {
			lower := strings.ToLower(body)
			return status == 200 && strings.HasPrefix(strings.TrimSpace(body), "[") &&
				strings.Contains(lower, `"id"`) &&
				(strings.Contains(lower, `"image"`) || strings.Contains(lower, `"imageid"`)) &&
				(strings.Contains(lower, `"command"`) || strings.Contains(lower, `"created"`) || strings.Contains(lower, `"names"`))
		},
	},
	{
		path:        "/version",
		signal:      "docker_version_exposed",
		title:       "Docker Engine Version API Exposed",
		severity:    "high",
		description: "Docker Engine version information was exposed publicly without authentication.",
		check: func(status int, body string) bool {
			lower := strings.ToLower(body)
			return status == 200 && strings.Contains(lower, "apiversion") && strings.Contains(lower, "minapiversion") && strings.Contains(lower, "gitcommit")
		},
	},

	// 2. Kubernetes API & Etcd Exposure
	{
		path:        "/api/v1/namespaces/default/pods",
		signal:      "k8s_api_pods_exposed",
		title:       "Kubernetes API Server Anonymous Pod Listing Exposure",
		severity:    "critical",
		description: "Kubernetes API server allows anonymous unauthenticated access to list cluster pods.",
		check: func(status int, body string) bool {
			lower := strings.ToLower(body)
			return status == 200 &&
				(strings.Contains(lower, `"kind": "podlist"`) ||
					(strings.Contains(lower, `"kind":"podlist"`) && strings.Contains(lower, "items")))
		},
	},
	{
		path:        "/v2/keys",
		signal:      "etcd_keyspace_exposed",
		title:       "etcd v2 Keyspace Unauthenticated Exposure",
		severity:    "critical",
		description: "etcd distributed key-value store was accessible without authentication, exposing cluster configuration, credentials, and secrets.",
		check: func(status int, body string) bool {
			lower := strings.ToLower(body)
			return status == 200 && strings.Contains(lower, `"action":`) && strings.Contains(lower, `"node":`)
		},
	},

	// 3. HashiCorp Vault & Consul API Exposure
	{
		path:        "/v1/sys/health",
		signal:      "vault_health_exposed",
		title:       "HashiCorp Vault Health API Exposed",
		severity:    "medium",
		description: "HashiCorp Vault system health endpoint is publicly accessible, leaking cluster name, version, and initialization status.",
		check: func(status int, body string) bool {
			lower := strings.ToLower(body)
			return (status == 200 || status == 429 || status == 473 || status == 501 || status == 503) &&
				strings.Contains(lower, "initialized") && strings.Contains(lower, "sealed") && strings.Contains(lower, "version")
		},
	},
	{
		path:        "/v1/agent/self",
		signal:      "consul_agent_exposed",
		title:       "HashiCorp Consul Agent API Exposed",
		severity:    "critical",
		description: "HashiCorp Consul Agent API was accessible without authentication, exposing internal cluster configuration and members.",
		check: func(status int, body string) bool {
			lower := strings.ToLower(body)
			return status == 200 && strings.Contains(lower, `"config"`) && strings.Contains(lower, `"datacenter"`) && strings.Contains(lower, `"node_name"`)
		},
	},

	// 4. Elasticsearch & Apache Solr Exposure
	{
		path:        "/_cat/indices?v",
		signal:      "elasticsearch_cat_indices_exposed",
		title:       "Elasticsearch Cluster Unauthenticated Indices Exposure",
		severity:    "critical",
		description: "Elasticsearch cluster allows unauthenticated access to indices and database storage.",
		check: func(status int, body string) bool {
			lower := strings.ToLower(body)
			return status == 200 && strings.Contains(lower, "health") && strings.Contains(lower, "status") && strings.Contains(lower, "index") && strings.Contains(lower, "docs.count")
		},
	},
	{
		path:        "/solr/admin/info/system?wt=json",
		signal:      "solr_system_info_exposed",
		title:       "Apache Solr Admin System Info Exposure",
		severity:    "high",
		description: "Apache Solr system administration API was accessible without authentication, exposing system properties, OS details, and JVM configurations.",
		check: func(status int, body string) bool {
			lower := strings.ToLower(body)
			return status == 200 && strings.Contains(lower, `"solr-spec-version"`) && strings.Contains(lower, `"system"`)
		},
	},
}

func (r *Runner) runCloudNativeExposure(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cloud_native_exposure", target); !ok {
		r.emitSkip("cloud_native_exposure", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil || u.Host == "" {
		return nil
	}

	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	baseline, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		baseline = httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	}

	// Wildcard / SPA pre-check
	wildcardURL := baseURL + "/akca-cloudnative-check-" + randomProbeToken()
	wRR, err := r.client.Do(ctx, "GET", wildcardURL, nil, nil)
	if err == nil && wRR.Response.StatusCode == 200 && len(wRR.Response.Body) > 100 {
		r.emitSkip("cloud_native_exposure", target, "wildcard/SPA catch-all detected")
		return nil
	}

	var out []ModuleFinding

	for _, probe := range cloudNativeProbes {
		if ctx.Err() != nil {
			break
		}

		probeURL := baseURL + probe.path
		rr, err := r.client.Do(ctx, "GET", probeURL, nil, nil)
		if err != nil {
			continue
		}

		if probe.check(rr.Response.StatusCode, rr.Response.Body) {
			// Round 2 confirmation
			rr2, err2 := r.client.Do(ctx, "GET", probeURL, nil, nil)
			if err2 == nil && probe.check(rr2.Response.StatusCode, rr2.Response.Body) {
				p := defaultPayload("cloud_native_exposure", probe.signal, probe.path, probe.signal)
				f := r.verifyAndBuild(ctx, "cloud_native_exposure", target, p, baseline, rr2, probe.signal, false, false, "", "")
				if f != nil {
					f.Severity = probe.severity
					f.Title = probe.title
					f.Description = probe.description + fmt.Sprintf(" Confirmed on '%s'.", probeURL)
					r.recordFinding(ctx, &out, f, "cloud_native_exposure", probe.signal)
				}
			}
		}
	}

	return out
}

func cloudNativeSignalConfirmed(signal string, status int, body string) bool {
	for _, probe := range cloudNativeProbes {
		if probe.signal == signal {
			return probe.check(status, body)
		}
	}
	return false
}
