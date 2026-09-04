package domtaint

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// StaticWarning represents a client-side vulnerability detected statically.
type StaticWarning struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Line        int    `json:"line,omitempty"`
	Snippet     string `json:"snippet"`
}

var (
	rePostMessageOrigin = regexp.MustCompile(`(?i)\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:function|\([^)]*\)\s*=>)`)
	reOriginCheck       = regexp.MustCompile(`(?i)(?:event|e)\.origin\s*(?:===|!==|==|!=|\.includes|\.indexOf)`)
	reDangerousEval     = regexp.MustCompile(`(?i)\beval\s*\(\s*(?:location|document|window\.)`)
	reDangerousInnerHTML = regexp.MustCompile(`(?i)\.innerHTML\s*=\s*(?:location|document|decodeURI)`)
)

// ParseTaintReports deserializes browser-reported taint log entries.
func ParseTaintReports(rawJSON, expectedCanary string) ([]TaintReport, error) {
	if strings.TrimSpace(rawJSON) == "" || rawJSON == "[]" || rawJSON == "null" {
		return nil, nil
	}

	var rawLogs []struct {
		Sink       string `json:"sink"`
		Category   string `json:"category"`
		Severity   string `json:"severity"`
		SinkValue  string `json:"sink_value"`
		StackTrace string `json:"stack_trace"`
		URL        string `json:"url"`
		Canary     string `json:"canary"`
		Timestamp  int64  `json:"timestamp"`
	}

	if err := json.Unmarshal([]byte(rawJSON), &rawLogs); err != nil {
		return nil, err
	}

	var reports []TaintReport
	for _, raw := range rawLogs {
		if expectedCanary != "" && !strings.Contains(raw.SinkValue, expectedCanary) {
			continue
		}

		cat := SinkDOMInjection
		switch raw.Category {
		case "code_execution":
			cat = SinkCodeExecution
		case "navigation":
			cat = SinkNavigation
		case "script_load":
			cat = SinkScriptLoad
		}

		reports = append(reports, TaintReport{
			Sink:       raw.Sink,
			Category:   cat,
			Severity:   raw.Severity,
			SinkValue:  raw.SinkValue,
			StackTrace: raw.StackTrace,
			URL:        raw.URL,
			Canary:     raw.Canary,
			Confirmed:  true,
			DetectedAt: time.UnixMilli(raw.Timestamp),
		})
	}

	return reports, nil
}

// StaticScanCode statically inspects JavaScript source code for high-risk DOM source/sink patterns.
func StaticScanCode(jsSource string) []StaticWarning {
	var warnings []StaticWarning

	// Check postMessage without origin verification
	if rePostMessageOrigin.MatchString(jsSource) {
		if !reOriginCheck.MatchString(jsSource) {
			warnings = append(warnings, StaticWarning{
				Title:       "PostMessage Listener Missing Origin Verification (Cross-Origin Data Injection)",
				Severity:    "high",
				Description: "The script registers a 'message' event listener but does not verify 'event.origin', allowing any malicious cross-origin iframe to send arbitrary payloads.",
				Snippet:     "window.addEventListener('message', ...)",
			})
		}
	}

	// Check direct source to eval
	if m := reDangerousEval.FindString(jsSource); m != "" {
		warnings = append(warnings, StaticWarning{
			Title:       "Direct DOM Source to eval() (DOM XSS)",
			Severity:    "critical",
			Description: "Client-side script passes unsanitized URL/DOM parameters directly into eval().",
			Snippet:     m,
		})
	}

	// Check direct source to innerHTML
	if m := reDangerousInnerHTML.FindString(jsSource); m != "" {
		warnings = append(warnings, StaticWarning{
			Title:       "Direct DOM Source to innerHTML (DOM XSS)",
			Severity:    "high",
			Description: "Client-side script writes unsanitized URL/DOM data directly to innerHTML.",
			Snippet:     m,
		})
	}

	return warnings
}
