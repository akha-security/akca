package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type devopsTarget struct {
	path     string
	title    string
	severity string
	verifier func(body string, status int) bool
}

func (r *Runner) runDevOpsExposure(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("devops_exposure", target); !ok {
		r.emitSkip("devops_exposure", target, reason)
		return nil
	}

	targets := []devopsTarget{
		// --- Cloud & Infrastructure State Files ---
		{
			path:     "/terraform.tfstate",
			title:    "Exposed Terraform State File (Cloud Secrets Disclosure)",
			severity: "critical",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, `"version"`) && strings.Contains(body, `"resources"`) && (strings.Contains(body, `"provider"`) || strings.Contains(body, `"attributes"`))
			},
		},
		{
			path:     "/.aws/credentials",
			title:    "Exposed AWS Credentials File",
			severity: "critical",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "[default]") && strings.Contains(body, "aws_access_key_id")
			},
		},
		{
			path:     "/.vscode/settings.json",
			title:    "Exposed VSCode Workspace Settings",
			severity: "medium",
			verifier: func(body string, status int) bool {
				var js map[string]interface{}
				return json.Unmarshal([]byte(body), &js) == nil && (strings.Contains(body, "database") || strings.Contains(body, "path") || strings.Contains(body, "editor"))
			},
		},
		{
			path:     "/helm/values.yaml",
			title:    "Exposed Helm Values Configuration",
			severity: "high",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "replicaCount:") || strings.Contains(body, "image:") || strings.Contains(body, "ingress:")
			},
		},
		{
			path:     "/k8s.yaml",
			title:    "Exposed Kubernetes Deployment Manifest",
			severity: "high",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "apiVersion:") && strings.Contains(body, "kind:")
			},
		},

		// --- Container & Orchestration Dashboards / APIs ---
		{
			path:     "/v2/_catalog",
			title:    "Unauthenticated Private Docker Registry API",
			severity: "critical",
			verifier: func(body string, status int) bool {
				trimmed := strings.TrimSpace(body)
				return strings.Contains(body, `"repositories"`) && strings.HasPrefix(trimmed, "{")
			},
		},
		{
			path:     "/api/v1/namespaces",
			title:    "Unauthenticated Kubernetes API Server",
			severity: "critical",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, `"kind": "NamespaceList"`) || strings.Contains(body, `"kind":"NamespaceList"`)
			},
		},
		{
			path:     "/v1/agent/self",
			title:    "Unauthenticated HashiCorp Consul Agent API",
			severity: "high",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, `"Config"`) && strings.Contains(body, `"Member"`)
			},
		},
		{
			path:     "/v1/sys/health",
			title:    "Exposed HashiCorp Vault Service Health API",
			severity: "medium",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, `"initialized"`) && strings.Contains(body, `"sealed"`)
			},
		},

		// --- Elasticsearch & Analytics Databases ---
		{
			path:     "/_cat/indices?v",
			title:    "Unauthenticated Elasticsearch Cluster API",
			severity: "critical",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "health") && strings.Contains(body, "status") && strings.Contains(body, "index") && strings.Contains(body, "docs.count")
			},
		},
		{
			path:     "/_cluster/health",
			title:    "Unauthenticated Elasticsearch Health API",
			severity: "high",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, `"cluster_name"`) && strings.Contains(body, `"number_of_nodes"`)
			},
		},
		{
			path:     "/app/kibana",
			title:    "Unauthenticated Kibana Dashboard Portal",
			severity: "high",
			verifier: func(body string, status int) bool {
				lower := strings.ToLower(body)
				return strings.Contains(lower, "kibana") && (strings.Contains(lower, "ui") || strings.Contains(lower, "config"))
			},
		},
		{
			path:     "/metrics",
			title:    "Exposed Prometheus Metrics Endpoint",
			severity: "medium",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "# HELP ") || strings.Contains(body, "# TYPE ") || strings.Contains(body, "go_goroutines")
			},
		},

		// --- CI/CD & Administration Portals ---
		{
			path:     "/script",
			title:    "Unauthenticated Jenkins Groovy Script Console (RCE)",
			severity: "critical",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "Groovy script") || strings.Contains(body, "Jenkins.instance")
			},
		},
		{
			path:     "/manager/html",
			title:    "Exposed Apache Tomcat Manager Application",
			severity: "high",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "Tomcat Web Application Manager") || strings.Contains(body, "Tomcat Server Administration")
			},
		},

		// --- Database Management Interfaces ---
		{
			path:     "/phpmyadmin/",
			title:    "Exposed phpMyAdmin Database Portal",
			severity: "high",
			verifier: func(body string, status int) bool {
				lower := strings.ToLower(body)
				return strings.Contains(lower, "phpmyadmin") && (strings.Contains(lower, "pma_username") || strings.Contains(lower, "welcome to"))
			},
		},
		{
			path:     "/adminer.php",
			title:    "Exposed Adminer Database Manager",
			severity: "high",
			verifier: func(body string, status int) bool {
				lower := strings.ToLower(body)
				return strings.Contains(lower, "adminer") && strings.Contains(lower, "database")
			},
		},

		// --- Diagnostics, Logs & Environment Disclosures ---
		{
			path:     "/phpinfo.php",
			title:    "Exposed PHP Info Diagnostic Page (System Disclosure)",
			severity: "high",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "<title>phpinfo()</title>") || strings.Contains(body, "PHP Version")
			},
		},
		{
			path:     "/server-status",
			title:    "Exposed Apache Server Status Page (Traffic & IP Disclosure)",
			severity: "medium",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "Apache Server Status") || strings.Contains(body, "Server Version")
			},
		},
		{
			path:     "/server-info",
			title:    "Exposed Apache Server Info Page",
			severity: "medium",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "Apache Server Information")
			},
		},
		{
			path:     "/nginx_status",
			title:    "Exposed Nginx Status Page",
			severity: "low",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, "Active connections:") && strings.Contains(body, "server accepts handled requests")
			},
		},

		// --- Environment Backup Files ---
		{
			path:     "/.env.bak",
			title:    "Exposed Backup Environment File (.env.bak)",
			severity: "critical",
			verifier: func(body string, status int) bool {
				return (strings.Contains(body, "DB_PASSWORD") || strings.Contains(body, "APP_KEY") || strings.Contains(body, "AWS_SECRET")) && strings.Contains(body, "=")
			},
		},
		{
			path:     "/.env.local",
			title:    "Exposed Local Environment Configuration File",
			severity: "critical",
			verifier: func(body string, status int) bool {
				return (strings.Contains(body, "DB_") || strings.Contains(body, "SECRET_KEY") || strings.Contains(body, "API_KEY")) && strings.Contains(body, "=")
			},
		},

		// --- API Documentation Disclosures ---
		{
			path:     "/swagger.json",
			title:    "Exposed Swagger OpenAPI Schema Definition",
			severity: "low",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, `"swagger":`) || strings.Contains(body, `"openapi":`)
			},
		},
		{
			path:     "/v2/api-docs",
			title:    "Exposed SpringFox Swagger API Docs",
			severity: "low",
			verifier: func(body string, status int) bool {
				return strings.Contains(body, `"swagger":"2.0"`) || strings.Contains(body, `"paths":`)
			},
		},

		// --- Backup Directory Listing (backup-directory-listing.yaml reference) ---
		{
			path:     "/backup/",
			title:    "Exposed Backup Directory Listing Enabled",
			severity: "medium",
			verifier: func(body string, status int) bool {
				return status == 200 && (strings.Contains(body, "<title>Index of") || strings.Contains(body, "Directory Listing for") || strings.Contains(body, "[To Parent Directory]") || strings.Contains(body, "Parent Directory"))
			},
		},
		{
			path:     "/backups/",
			title:    "Exposed Backups Directory Listing Enabled",
			severity: "medium",
			verifier: func(body string, status int) bool {
				return status == 200 && (strings.Contains(body, "<title>Index of") || strings.Contains(body, "Directory Listing for") || strings.Contains(body, "[To Parent Directory]") || strings.Contains(body, "Parent Directory"))
			},
		},
		{
			path:     "/php/backup/",
			title:    "Exposed PHP Backup Directory Listing Enabled",
			severity: "medium",
			verifier: func(body string, status int) bool {
				return status == 200 && (strings.Contains(body, "<title>Index of") || strings.Contains(body, "Directory Listing for") || strings.Contains(body, "[To Parent Directory]") || strings.Contains(body, "Parent Directory"))
			},
		},
		{
			path:     "/bak/",
			title:    "Exposed Bak Directory Listing Enabled",
			severity: "medium",
			verifier: func(body string, status int) bool {
				return status == 200 && (strings.Contains(body, "<title>Index of") || strings.Contains(body, "Directory Listing for") || strings.Contains(body, "[To Parent Directory]") || strings.Contains(body, "Parent Directory"))
			},
		},
		{
			path:     "/dump/",
			title:    "Exposed SQL Dump Directory Listing Enabled",
			severity: "medium",
			verifier: func(body string, status int) bool {
				return status == 200 && (strings.Contains(body, "<title>Index of") || strings.Contains(body, "Directory Listing for") || strings.Contains(body, "[To Parent Directory]") || strings.Contains(body, "Parent Directory"))
			},
		},
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

	// Wildcard / SPA check
	wildcardURL := base + "/akca-devops-check-" + randomProbeToken()
	wRR, err := r.client.Do(ctx, "GET", wildcardURL, nil, nil)
	if err == nil && wRR.Response.StatusCode == 200 && len(wRR.Response.Body) > 100 {
		r.emitSkip("devops_exposure", target, "wildcard/SPA catch-all detected")
		return nil
	}

	for _, dt := range targets {
		if ctx.Err() != nil {
			break
		}

		targetURL := base + dt.path
		probeTarget := originTarget
		probeTarget.EndpointURL = targetURL

		rr, err := r.probe(ctx, probeTarget, "")
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}

		// Reject redirects away from the probed infrastructure path (e.g. 302 to login or root)
		if rr.Response.Redirected {
			finalClean := strings.TrimRight(rr.Response.FinalURL, "/")
			origClean := strings.TrimRight(targetURL, "/")
			if finalClean != origClean {
				continue
			}
		}

		if dt.verifier(rr.Response.Body, rr.Response.StatusCode) {
			signal := fmt.Sprintf("devops_exposure_%s", strings.ReplaceAll(strings.TrimPrefix(dt.path, "/"), "/", "_"))
			p := defaultPayload("devops_exposure", dt.path, dt.path, signal)
			f := r.verifyAndBuild(ctx, "devops_exposure", probeTarget, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = dt.title
				f.Severity = dt.severity
				f.Description = fmt.Sprintf("Exposed infrastructure endpoint/file '%s' was publicly accessible and verified via strict schema parsing.", dt.path)
				r.recordFinding(ctx, &out, f, "devops_exposure", signal)
			}
		}
	}

	return out
}

func devopsExposureSignalConfirmed(signal string, status int, body string) bool {
	if status != 200 || !strings.HasPrefix(signal, "devops_exposure_") {
		return false
	}
	suffix := strings.TrimPrefix(signal, "devops_exposure_")
	lower := strings.ToLower(body)
	switch suffix {
	case "terraform.tfstate":
		return strings.Contains(body, `"version"`) && strings.Contains(body, `"resources"`) &&
			(strings.Contains(body, `"provider"`) || strings.Contains(body, `"attributes"`))
	case ".aws_credentials":
		return strings.Contains(body, "[default]") && strings.Contains(body, "aws_access_key_id")
	case ".vscode_settings.json":
		var js map[string]interface{}
		return json.Unmarshal([]byte(body), &js) == nil &&
			(strings.Contains(body, "database") || strings.Contains(body, "path") || strings.Contains(body, "editor"))
	case "helm_values.yaml":
		return strings.Contains(body, "replicaCount:") || strings.Contains(body, "image:") || strings.Contains(body, "ingress:")
	case "k8s.yaml":
		return strings.Contains(body, "apiVersion:") && strings.Contains(body, "kind:")
	case "v2__catalog":
		return strings.Contains(body, `"repositories"`)
	case "api_v1_namespaces":
		return strings.Contains(body, `"kind": "NamespaceList"`) || strings.Contains(body, `"kind":"NamespaceList"`)
	case "v1_agent_self":
		return strings.Contains(body, `"Config"`) && strings.Contains(body, `"Member"`)
	case "v1_sys_health":
		return strings.Contains(body, `"initialized"`) && strings.Contains(body, `"sealed"`)
	case "_cat_indices?v":
		return strings.Contains(body, "health") && strings.Contains(body, "status") && strings.Contains(body, "index")
	case "_cluster_health":
		return strings.Contains(body, `"cluster_name"`) && strings.Contains(body, `"number_of_nodes"`)
	case "app_kibana":
		return strings.Contains(lower, "kibana") && (strings.Contains(lower, "ui") || strings.Contains(lower, "config"))
	case "metrics":
		return strings.Contains(body, "# HELP ") || strings.Contains(body, "# TYPE ") || strings.Contains(body, "go_goroutines")
	case "script":
		return strings.Contains(body, "Groovy script") || strings.Contains(body, "Jenkins.instance")
	case "manager_html":
		return strings.Contains(body, "Tomcat Web Application Manager") || strings.Contains(body, "Tomcat Server Administration")
	case "phpmyadmin_":
		return strings.Contains(lower, "phpmyadmin") && (strings.Contains(lower, "pma_username") || strings.Contains(lower, "welcome to"))
	case "adminer.php":
		return strings.Contains(lower, "adminer") && strings.Contains(lower, "database")
	case "phpinfo.php":
		return strings.Contains(body, "<title>phpinfo()</title>") || strings.Contains(body, "PHP Version")
	case "server-status":
		return strings.Contains(body, "Apache Server Status") || strings.Contains(body, "Server Version")
	case "server-info":
		return strings.Contains(body, "Apache Server Information")
	case "nginx_status":
		return strings.Contains(body, "Active connections:") && strings.Contains(body, "server accepts handled requests")
	case ".env.bak":
		return (strings.Contains(body, "DB_PASSWORD") || strings.Contains(body, "APP_KEY") || strings.Contains(body, "AWS_SECRET")) && strings.Contains(body, "=")
	case ".env.local":
		return (strings.Contains(body, "DB_") || strings.Contains(body, "SECRET_KEY") || strings.Contains(body, "API_KEY")) && strings.Contains(body, "=")
	case "swagger.json":
		return strings.Contains(body, `"swagger":`) || strings.Contains(body, `"openapi":`)
	case "v2_api-docs":
		return strings.Contains(body, `"swagger":"2.0"`) || strings.Contains(body, `"paths":`)
	case "backup_", "backups_", "php_backup_", "bak_", "dump_":
		return strings.Contains(body, "<title>Index of") ||
			strings.Contains(body, "Directory Listing for") ||
			strings.Contains(body, "[To Parent Directory]") ||
			strings.Contains(body, "Parent Directory")
	default:
		return false
	}
}
