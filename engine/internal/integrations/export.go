package integrations

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/akha-security/akca/engine/internal/report"
)

type Kind string

const (
	Jira         Kind = "jira"
	GitHubIssues Kind = "github_issues"
	Slack        Kind = "slack"
	Teams        Kind = "teams"
	DefectDojo   Kind = "defectdojo"
	WAF          Kind = "waf"
)

type Envelope struct {
	Integration    Kind `json:"integration"`
	ConfirmedCount int  `json:"confirmed_count"`
	FilteredCount  int  `json:"filtered_unproven_count"`
	Payload        any  `json:"payload"`
}

// Export deliberately accepts report findings rather than raw detections.
// Every external integration shares the same proof gate and redaction path.
func Export(kind Kind, findings []report.FindingEntry) ([]byte, error) {
	confirmed := submissionReady(findings)
	var payload any
	switch kind {
	case Jira:
		payload = issuePayloads(confirmed, "jira")
	case GitHubIssues:
		payload = issuePayloads(confirmed, "github")
	case Slack:
		payload = slackPayload(confirmed)
	case Teams:
		payload = teamsPayload(confirmed)
	case DefectDojo:
		payload = defectDojoPayload(confirmed)
	case WAF:
		payload = wafPayload(confirmed)
	default:
		return nil, fmt.Errorf("unsupported integration %q", kind)
	}
	return json.MarshalIndent(Envelope{
		Integration: kind, ConfirmedCount: len(confirmed),
		FilteredCount: len(findings) - len(confirmed), Payload: payload,
	}, "", "  ")
}

func submissionReady(findings []report.FindingEntry) []report.FindingEntry {
	out := make([]report.FindingEntry, 0, len(findings))
	for _, finding := range findings {
		if !strings.EqualFold(strings.TrimSpace(finding.Confidence), "confirmed") ||
			!finding.HTTPEvidence.ProofSatisfied {
			continue
		}
		finding.Title = report.RedactString(finding.Title)
		finding.Summary = report.RedactString(finding.Summary)
		finding.Description = report.RedactString(finding.Description)
		finding.EndpointURL = report.RedactString(finding.EndpointURL)
		finding.Parameter = report.RedactString(finding.Parameter)
		finding.HTTPEvidence.Payload = report.RedactString(finding.HTTPEvidence.Payload)
		finding.HTTPEvidence.RawRequest = ""
		finding.HTTPEvidence.RawResponse = ""
		out = append(out, finding)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func issuePayloads(findings []report.FindingEntry, provider string) []map[string]any {
	issues := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		body := strings.Join([]string{
			"Confirmed by Akca proof policy.",
			"",
			"Severity: " + finding.Severity,
			"Class: " + finding.VulnClass,
			"Endpoint: " + finding.EndpointURL,
			"Parameter: " + finding.Parameter,
			"",
			finding.Description,
			"",
			"Remediation: " + finding.Remediation,
		}, "\n")
		issue := map[string]any{
			"title": finding.Title, "description": body,
			"labels": []string{"security", "akca-confirmed", finding.Severity, finding.VulnClass},
		}
		if provider == "github" {
			issue["body"] = body
			delete(issue, "description")
		} else {
			issue["issue_type"] = "Bug"
			issue["priority"] = jiraPriority(finding.Severity)
		}
		issues = append(issues, issue)
	}
	return issues
}

func slackPayload(findings []report.FindingEntry) map[string]any {
	blocks := []map[string]any{{
		"type": "header", "text": map[string]string{"type": "plain_text",
			"text": fmt.Sprintf("Akca: %d confirmed finding(s)", len(findings))},
	}}
	for _, finding := range findings {
		text := fmt.Sprintf("*%s* · %s\n%s\n`%s`", strings.ToUpper(finding.Severity),
			finding.Title, finding.EndpointURL, finding.VulnClass)
		blocks = append(blocks, map[string]any{
			"type": "section", "text": map[string]string{"type": "mrkdwn", "text": text},
		})
	}
	return map[string]any{"blocks": blocks}
}

func teamsPayload(findings []report.FindingEntry) map[string]any {
	body := []map[string]any{{
		"type": "TextBlock", "size": "Large", "weight": "Bolder",
		"text": fmt.Sprintf("Akca: %d confirmed finding(s)", len(findings)),
	}}
	for _, finding := range findings {
		body = append(body, map[string]any{
			"type": "TextBlock", "wrap": true,
			"text": fmt.Sprintf("[%s] %s\n%s", strings.ToUpper(finding.Severity), finding.Title, finding.EndpointURL),
		})
	}
	return map[string]any{
		"type": "AdaptiveCard", "version": "1.4",
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "body": body,
	}
}

func defectDojoPayload(findings []report.FindingEntry) map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		out = append(out, map[string]any{
			"title": finding.Title, "severity": strings.Title(strings.ToLower(finding.Severity)),
			"description": finding.Description, "mitigation": finding.Remediation,
			"endpoint": finding.EndpointURL, "unique_id_from_tool": strconv.FormatInt(finding.ID, 10),
			"active": true, "verified": true, "false_p": false,
		})
	}
	return map[string]any{"scan_type": "Akca Scan", "findings": out}
}

func wafPayload(findings []report.FindingEntry) map[string]any {
	rules := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		if !isInjectionClass(finding.VulnClass) || strings.TrimSpace(finding.HTTPEvidence.Payload) == "" {
			continue
		}
		id := wafRuleID(finding)
		target := "ARGS"
		switch strings.ToLower(finding.HTTPEvidence.Location) {
		case "header", "headers":
			target = "REQUEST_HEADERS"
		case "body", "json", "form":
			target = "ARGS_POST"
		case "cookie":
			target = "REQUEST_COOKIES"
		}
		if finding.Parameter != "" {
			target += ":" + wafToken(finding.Parameter)
		}
		rule := fmt.Sprintf(
			`SecRule %s "@contains %s" "id:%d,phase:2,log,pass,t:none,tag:'akca-candidate',msg:'Akca confirmed %s; review before deny mode'"`,
			target, modSecurityQuote(finding.HTTPEvidence.Payload), id, wafToken(finding.VulnClass))
		rules = append(rules, map[string]any{
			"id": id, "mode": "monitor_only", "requires_human_approval": true,
			"finding_id": finding.ID, "rule": rule,
		})
	}
	return map[string]any{
		"format": "modsecurity", "default_mode": "monitor_only",
		"warning": "Validate in staging before changing pass to deny.", "rules": rules,
	}
}

func isInjectionClass(class string) bool {
	switch strings.ToLower(strings.TrimSpace(class)) {
	case "sqli", "sql_injection", "xss", "command_injection", "ssti", "template_injection", "xpath_injection", "ldap_injection":
		return true
	default:
		return false
	}
}

func modSecurityQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", `\n`)
	return `"` + value + `"`
}

func wafToken(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func wafRuleID(finding report.FindingEntry) uint32 {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s",
		finding.ID, finding.VulnClass, finding.EndpointURL, finding.Parameter)))
	return 9000000 + binary.BigEndian.Uint32(sum[:4])%999999
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func jiraPriority(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	default:
		return "Low"
	}
}
