package modules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
)

var (
	sstiMathExprRe   = regexp.MustCompile(`(\d{1,7})\s*[\*x]\s*(\d{1,7})`)
	sstiErrorTraceRe = regexp.MustCompile(`(?i)(jinja2\.exceptions|twig\\error|freemarker\.core|template syntax error|undefined filter|templateerror)`)
)

// sstiSignalConfirmed rejects reflection-only and coincidental numeric matches.
func sstiSignalConfirmed(p payloadgen.Payload, body, baseline, signal string) bool {
	if signal == "" || body == "" {
		return false
	}
	// Payload echoed verbatim means the server did not evaluate a template.
	if strings.Contains(body, p.Value) && !strings.Contains(baseline, p.Value) {
		return false
	}
	switch signal {
	case "math_evaluation", "template_evaluation_49":
		return sstiMathProductConfirmed(p.Value, body, baseline)
	case "error_trace":
		return false
	case "config_leak":
		lower := strings.ToLower(body)
		baseLower := strings.ToLower(baseline)
		for _, marker := range []string{"secret_key", "database_uri", "sqlalchemy", "aws_secret"} {
			if strings.Contains(lower, marker) && !strings.Contains(baseLower, marker) {
				return true
			}
		}
		return false
	case "command_output", "separator_output":
		return false
	case "string_multiply_eval":
		return false
	default:
		return false
	}
}

func sstiMathProductConfirmed(payload, body, baseline string) bool {
	m := sstiMathExprRe.FindStringSubmatch(payload)
	if m == nil {
		return false
	}
	a, errA := strconv.Atoi(m[1])
	b, errB := strconv.Atoi(m[2])
	if errA != nil || errB != nil || a < 2 || b < 2 {
		return false
	}
	product := strconv.Itoa(a * b)
	if len(product) < 3 {
		return false
	}
	if strings.Contains(baseline, product) {
		return false
	}
	if !strings.Contains(body, product) {
		return false
	}

	// Verify that the product appears as a standalone token at least once in the body.
	hasStandalone := false
	start := 0
	for {
		idx := strings.Index(body[start:], product)
		if idx == -1 {
			break
		}
		actualIdx := start + idx
		isWordStart := actualIdx == 0 || body[actualIdx-1] < '0' || body[actualIdx-1] > '9'
		endIdx := actualIdx + len(product)
		isWordEnd := endIdx == len(body) || body[endIdx] < '0' || body[endIdx] > '9'
		if isWordStart && isWordEnd {
			hasStandalone = true
			break
		}
		start = actualIdx + 1
	}
	if !hasStandalone {
		return false
	}

	diff := bodyDiffRatio(baseline, body)
	return diff >= 0.01
}

func sstiCommandOutputConfirmed(body, baseline string) bool {
	lower := strings.ToLower(body)
	baseLower := strings.ToLower(baseline)
	for _, m := range []string{"uid=", "gid=", "groups=", "root:", "www-data"} {
		if strings.Contains(lower, m) && !strings.Contains(baseLower, m) {
			return true
		}
	}
	return false
}

func bodyDiffRatio(a, b string) float64 {
	if a == b {
		return 0
	}
	aLen, bLen := len(a), len(b)
	maxLen := aLen
	if bLen > maxLen {
		maxLen = bLen
	}
	if maxLen == 0 {
		return 0
	}

	// Trim the usually-large equal edges before running Myers. Besides making
	// the comparison cheap for web responses, this ensures that an insertion
	// near the beginning does not shift every later byte into a false mismatch.
	prefix := 0
	for prefix < aLen && prefix < bLen && a[prefix] == b[prefix] {
		prefix++
	}
	aEnd, bEnd := aLen, bLen
	for aEnd > prefix && bEnd > prefix && a[aEnd-1] == b[bEnd-1] {
		aEnd--
		bEnd--
	}

	midA, midB := a[prefix:aEnd], b[prefix:bEnd]
	editDistance := myersInsertDeleteDistance(midA, midB)
	midLCS := (len(midA) + len(midB) - editDistance) / 2
	lcsLen := prefix + (aLen - aEnd) + midLCS
	return 1 - float64(lcsLen)/float64(maxLen)
}

// myersInsertDeleteDistance returns the shortest edit script length when the
// allowed operations are insertion and deletion. The corresponding LCS length
// is (len(a)+len(b)-distance)/2.
func myersInsertDeleteDistance(a, b string) int {
	n, m := len(a), len(b)
	if n == 0 {
		return m
	}
	if m == 0 {
		return n
	}
	max := n + m
	offset := max
	v := make([]int, 2*max+1)
	for d := 0; d <= max; d++ {
		for k := -d; k <= d; k += 2 {
			idx := offset + k
			var x int
			if k == -d || (k != d && v[idx-1] < v[idx+1]) {
				x = v[idx+1]
			} else {
				x = v[idx-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[idx] = x
			if x >= n && y >= m {
				return d
			}
		}
	}
	return max
}
