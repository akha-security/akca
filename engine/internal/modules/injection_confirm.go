package modules

import (
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
)

var (
	sqliErrorRe = regexp.MustCompile(`(?i)(you have an error in your sql syntax|mysql.*syntax|mysql\s+error|mariadb.*syntax|mariadb\s+error|sqlite3?\.OperationalError|postgresql.*ERROR.*syntax|postgresql\s+error|pg_query\(\)|ora-\d{4,5}|sqlstate\[|unclosed quotation mark|quoted string not properly terminated|warning:\s*mysql|syntax error at or near|incorrect syntax near\s+'|microsoft ole db provider|odbc sql server driver|pg::syntaxerror|PDOException.*SQLSTATE|java\.sql\.SQLException|com\.mysql\.jdbc|org\.postgresql\.util\.PSQLException|sql\s+syntax\s+error|syntax\s+error\s+near|db2.*cli driver|db2.*sql error|sybase.*error|adaptive server|informix.*error|h2 database.*error|cockroachdb.*error|crdb.*internal|clickhouse.*exception|code:\s*\d+.*DB::Exception|snowflake.*error|sql compilation error|duckdb.*error)`)
	cmdOutRe    = regexp.MustCompile(`(?i)\buid=\d+(?:\([a-z0-9._-]+\))?\s+gid=\d+(?:\([a-z0-9._-]+\))?(?:\s+groups=\d+(?:\([a-z0-9._-]+\))?(?:,\d+(?:\([a-z0-9._-]+\))?)*)?`)
	cmdWinDirRe = regexp.MustCompile(`(?is)\bvolume serial number is\b.{0,500}\bdirectory of\b`)
	xssExecRe   = regexp.MustCompile(`(?i)(<script[^>]*>[\s\S]{0,200}alert\s*\(|<svg[^>]+onload\s*=|<img[^>]+onerror\s*=)`)
)

func injectionPayloadReflected(payload, body, baseline string) bool {
	if payload == "" {
		return false
	}
	return strings.Contains(body, payload) && !strings.Contains(baseline, payload)
}

func sqliSignalConfirmed(p payloadgen.Payload, body, baseline, signal string) bool {
	if signal == "" || body == "" {
		return false
	}
	if injectionPayloadReflected(p.Value, body, baseline) && signal != "error_based" {
		return false
	}
	// Normalize volatile fields (timestamps, UUIDs, CSRF tokens) before
	// comparing bodies so that dynamic page elements don't inflate the diff.
	normBody := normalizeVolatileFields(body)
	normBase := normalizeVolatileFields(baseline)
	switch signal {
	case "error_based":
		return sqliErrorInBody(body, baseline)
	case "boolean_pair_confirmed":
		// This signal is emitted only after the bespoke alternating true/false
		// verifier has reproduced both branches on the same injection surface.
		return strings.TrimSpace(body) != ""
	case "union_signal":
		return unionSignalConfirmed(p.Value, body, baseline)
	case "timing_differential", "stacked_timing":
		return true
	default:
		return normBody != normBase && bodyDiffRatio(normBase, normBody) >= 0.03
	}
}

func xssSignalConfirmed(p payloadgen.Payload, body, baseline, signal string) bool {
	if signal == "" || body == "" {
		return false
	}

	switch signal {
	case "reflected_encoded":
		return false
	case "reflected":
		if injectionPayloadReflected(p.Value, body, baseline) {
			if sqliErrorRe.MatchString(body) {
				return false
			}
			return xssExecutableReflection(body, p.Value) && !xssExecutableReflection(baseline, p.Value)
		}
		return false
	case "reflected_partial":
		return false
	case "dom_execution", "stored_tracking":
		if sqliErrorRe.MatchString(body) {
			return false
		}
		return xssExecRe.MatchString(body) && !xssExecRe.MatchString(baseline)
	default:
		if sqliErrorRe.MatchString(body) {
			return false
		}
		return xssExecRe.MatchString(body) && !xssExecRe.MatchString(baseline)
	}
}

func cmdInjSignalConfirmed(p payloadgen.Payload, body, baseline, signal string) bool {
	if signal == "" {
		return false
	}
	if injectionPayloadReflected(p.Value, body, baseline) {
		return false
	}
	switch signal {
	case "canary_output":
		expected := commandExpectedMarker(p)
		return expected != "" && !strings.Contains(p.Value, expected) &&
			strings.Contains(body, expected) && !strings.Contains(baseline, expected)
	case "separator_output", "command_output":
		return commandOutputForPayload(p, body) && !commandOutputForPayload(p, baseline)
	case "timing_signal":
		return true
	default:
		return false
	}
}

func commandOutputForPayload(p payloadgen.Payload, body string) bool {
	signal := strings.ToLower(p.ExpectedSignal)
	value := strings.ToLower(p.Value)
	switch {
	case strings.Contains(signal, "win") && strings.Contains(value, "dir"):
		return cmdWinDirRe.MatchString(body)
	case strings.Contains(signal, "win") && strings.Contains(value, "whoami"):
		// A bare DOMAIN\user line is accepted only for an explicit whoami
		// payload; arbitrary backslashes elsewhere in HTML are not evidence.
		for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
			line = strings.TrimSpace(line)
			if regexp.MustCompile(`(?i)^[a-z0-9._-]+\\[a-z0-9.$_-]+$`).MatchString(line) {
				return true
			}
		}
		return false
	case strings.Contains(value, "id") || strings.Contains(signal, "command_output"):
		return cmdOutRe.MatchString(body)
	default:
		return false
	}
}
