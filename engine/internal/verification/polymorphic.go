package verification

import (
	"regexp"
	"strconv"
	"strings"
)

var sstiMathVariantRE = regexp.MustCompile(`(\d{1,7})\s*\*\s*(\d{1,7})`)

func PolymorphicVariants(vulnClass, payload string) []string {
	switch vulnClass {
	case "xss":
		return []string{
			payload,
			strings.ReplaceAll(payload, "alert(1)", "confirm(1)"),
			`<img src=x onerror=alert(1)>`,
		}
	case "sqli":
		return []string{
			payload,
			strings.ReplaceAll(payload, "'", `"`),
			`' OR 1=1--`,
		}
	case "ssti":
		match := sstiMathVariantRE.FindStringSubmatchIndex(payload)
		if match == nil {
			return nil
		}
		left, errLeft := strconv.Atoi(payload[match[2]:match[3]])
		right, errRight := strconv.Atoi(payload[match[4]:match[5]])
		if errLeft != nil || errRight != nil {
			return nil
		}
		build := func(a, b int) string {
			return payload[:match[0]] + strconv.Itoa(a) + "*" + strconv.Itoa(b) + payload[match[1]:]
		}
		return []string{payload, build(left+2, right+4), build(left+6, right+8)}
	case "xxe":
		return []string{payload, strings.ReplaceAll(payload, "AKCA_XXE_TEST", "AKCA_XXE_VARIANT"), payload + " "}
	default:
		// Whitespace/case changes are not meaningful polymorphic evidence for
		// arbitrary modules (JWT, cache, authorization, etc.). Those modules
		// have their own deterministic signal guards.
		return nil
	}
}

func ConfirmPolymorphic(hits []bool) bool {
	if len(hits) == 0 {
		return false
	}
	if len(hits) < 2 {
		return hits[0]
	}
	count := 0
	for _, h := range hits {
		if h {
			count++
		}
	}
	return count >= 2
}
