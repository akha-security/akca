package modules

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	privilegedRoleRE = regexp.MustCompile(`(?i)["']?(?:role|access_?level|privilege|account_?type)["']?(?:\s+is\s+|\s*[:=]\s*)["']?(?:admin|administrator|elevated|superuser|root)\b`)
	lowRoleRE        = regexp.MustCompile(`(?i)["']?(?:role|access_?level|privilege|account_?type)["']?(?:\s+is\s+|\s*[:=]\s*)["']?(?:user|member|guest|basic|viewer)\b`)
	adminTrueRE      = regexp.MustCompile(`(?i)["']?is_?admin["']?\s*[:=]\s*(?:true|1)\b`)
	adminFalseRE     = regexp.MustCompile(`(?i)["']?is_?admin["']?\s*[:=]\s*(?:false|0)\b`)
	permissionRE     = regexp.MustCompile(`(?i)["']?(?:permissions?|scopes?|capabilities)["']?\s*[:=]\s*(?:\[[^\]]*(?:admin|\*|write|all)[^\]]*\]|["'](?:admin|\*|write|all)["'])`)
	grantRE          = regexp.MustCompile(`(?i)\b(?:authorization|access|privilege)\b.{0,32}\b(?:granted|allowed|elevated|administrator)\b`)
	echoContextRE    = regexp.MustCompile(`(?i)\b(?:received|submitted|request|payload|input|query|parameter|echo(?:ed)?)\b`)
)

func privilegeEscalationSignal(body, baseline string) bool {
	if body == baseline || strings.TrimSpace(body) == "" {
		return false
	}
	bodyPrivileged := privilegedRoleRE.MatchString(body) || adminTrueRE.MatchString(body) ||
		permissionRE.MatchString(body) || grantRE.MatchString(body)
	if !bodyPrivileged {
		return false
	}
	if privilegedRoleRE.MatchString(baseline) || adminTrueRE.MatchString(baseline) ||
		permissionRE.MatchString(baseline) || grantRE.MatchString(baseline) {
		return false
	}
	baselineLowPrivilege := lowRoleRE.MatchString(baseline) || adminFalseRE.MatchString(baseline)
	return baselineLowPrivilege || grantRE.MatchString(body)
}

// payloadSemanticallyReflected catches exact and re-serialized JSON echoes,
// including the common {"received": <request>} error/debug response shape.
func payloadSemanticallyReflected(payload, response string) bool {
	var sent, got any
	if json.Unmarshal([]byte(payload), &sent) != nil || json.Unmarshal([]byte(response), &got) != nil {
		return echoContextRE.MatchString(response)
	}
	if jsonValuesEqual(sent, got) {
		return true
	}
	return jsonEchoContainer(got, sent)
}

func jsonEchoContainer(value, sent any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			switch strings.ToLower(key) {
			case "received", "submitted", "request", "payload", "input", "query", "parameters":
				if jsonValuesEqual(child, sent) {
					return true
				}
			}
			if jsonEchoContainer(child, sent) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if jsonEchoContainer(child, sent) {
				return true
			}
		}
	}
	return false
}

func jsonValuesEqual(a, b any) bool {
	aa, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(aa) == string(bb)
}
