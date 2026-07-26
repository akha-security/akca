package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/akha-security/akca/engine/internal/app"
	"github.com/akha-security/akca/engine/internal/benchmark"
	"github.com/akha-security/akca/engine/internal/browserpool"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/report"
	"github.com/akha-security/akca/engine/internal/storage"
)

const (
	version = "1.0.0"
	uiWidth = 68
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  NEON PULSE — True-Color Design System
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const (
	rst = "\033[0m"
	bld = "\033[1m"
	dm  = "\033[2m"
	itl = "\033[3m"
	ul  = "\033[4m"

	// ── Neon Pulse Palette (True-Color 24-bit) ──
	// Soft, eye-friendly pastel neons on dark backgrounds
	cLavender = "\033[38;2;180;167;214m" // primary accent — titles, frames
	cMint     = "\033[38;2;130;210;180m" // success states
	cAmber    = "\033[38;2;244;211;94m"  // warnings, medium severity
	cRose     = "\033[38;2;232;146;142m" // errors, high severity
	cIce      = "\033[38;2;137;207;240m" // info, links, endpoints
	cPeach    = "\033[38;2;255;183;148m" // critical severity
	cSilver   = "\033[38;2;200;200;210m" // primary text
	cSlate    = "\033[38;2;120;120;140m" // dim/secondary text
	cGhost    = "\033[38;2;80;80;100m"   // very dim — frames, separators
	cCloud    = "\033[38;2;220;220;235m" // bright text
	cLilac    = "\033[38;2;200;180;230m" // verified findings
	cTeal     = "\033[38;2;100;200;200m" // phases
	cSky      = "\033[38;2;160;200;255m" // stats
	cCoral    = "\033[38;2;255;127;110m" // bold critical
	cFrost    = "\033[38;2;180;220;255m" // badges

	// Bold variants
	bLavender = "\033[1;38;2;180;167;214m"
	bMint     = "\033[1;38;2;130;210;180m"
	bAmber    = "\033[1;38;2;244;211;94m"
	bRose     = "\033[1;38;2;232;146;142m"
	bIce      = "\033[1;38;2;137;207;240m"
	bPeach    = "\033[1;38;2;255;183;148m"
	bCloud    = "\033[1;38;2;220;220;235m"
	bLilac    = "\033[1;38;2;200;180;230m"
	bTeal     = "\033[1;38;2;100;200;200m"
	bCoral    = "\033[1;38;2;255;127;110m"
)

// ── Gradient generator ──────────────────────────────────────────────────────
// Produces a true-color string where each character smoothly transitions
// between two RGB endpoints. Gives the banner its signature lavender→mint glow.
func gradient(text string, r1, g1, b1, r2, g2, b2 int) string {
	runes := []rune(text)
	n := len(runes)
	if n <= 1 {
		return fmt.Sprintf("\033[38;2;%d;%d;%dm%s%s", r1, g1, b1, text, rst)
	}
	var sb strings.Builder
	for i, ch := range runes {
		t := float64(i) / float64(n-1)
		r := int(float64(r1) + t*float64(r2-r1))
		g := int(float64(g1) + t*float64(g2-g1))
		b := int(float64(b1) + t*float64(b2-b1))
		sb.WriteString(fmt.Sprintf("\033[38;2;%d;%d;%dm%c", r, g, b, ch))
	}
	sb.WriteString(rst)
	return sb.String()
}

// ── Box Drawing Primitives ──────────────────────────────────────────────────
// Creates the premium panel aesthetic with Unicode box-drawing characters.
const (
	boxTL = "╭" // top-left
	boxTR = "╮" // top-right
	boxBL = "╰" // bottom-left
	boxBR = "╯" // bottom-right
	boxH  = "─" // horizontal
	boxV  = "│" // vertical
	boxML = "├" // middle-left
	boxMR = "┤" // middle-right

	// Double-line variants for emphasis
	dBoxTL = "╔"
	dBoxTR = "╗"
	dBoxBL = "╚"
	dBoxBR = "╝"
	dBoxH  = "═"
	dBoxV  = "║"
)

func boxLine(left, fill, right string, width int) string {
	return cGhost + left + strings.Repeat(fill, width+2) + right + rst
}

func boxText(text string, width int) string {
	// Strip ANSI codes for length calculation
	visLen := visibleLen(text)
	padding := width - visLen
	if padding < 0 {
		padding = 0
	}
	return cGhost + boxV + rst + " " + text + strings.Repeat(" ", padding) + " " + cGhost + boxV + rst
}

func visibleLen(s string) int {
	inEsc := false
	count := 0
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		count++
	}
	return count
}

// padToWidth pads a visible string to the given width
func padToWidth(s string, width int) string {
	vl := visibleLen(s)
	if vl >= width {
		return s
	}
	return s + strings.Repeat(" ", width-vl)
}

// safeTerminalText keeps untrusted target data from breaking panels or
// injecting terminal control sequences. Whitespace is collapsed so every
// value stays on the line owned by the renderer.
func safeTerminalText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func truncateText(s string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}

func isTTY() bool {
	info, err := os.Stderr.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  BANNER — Gradient ASCII Art
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func printBanner() {
	bannerLines := []string{
		` █████╗ ██╗  ██╗ ██████╗ █████╗ `,
		`██╔══██╗██║ ██╔╝██╔════╝██╔══██╗`,
		`███████║█████╔╝ ██║     ███████║`,
		`██╔══██║██╔═██╗ ██║     ██╔══██║`,
		`██║  ██║██║  ██╗╚██████╗██║  ██║`,
		`╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝`,
	}

	// Gradient palette: Lavender (180,167,214) → Teal (100,200,200)
	// Each line gets a slightly different hue for a wave effect
	type rgb struct{ r, g, b int }
	lineColors := []rgb{
		{180, 167, 214}, // lavender
		{165, 175, 212}, // lavender-blue
		{145, 185, 208}, // steel
		{125, 195, 205}, // teal-shift
		{110, 200, 200}, // teal
		{100, 205, 195}, // teal-mint
	}

	fmt.Fprint(os.Stderr, "\n")
	for i, line := range bannerLines {
		c := lineColors[i]
		// Per-line gradient from the base color toward a brighter variant
		fmt.Fprintf(os.Stderr, "%s\n",
			gradient(line, c.r, c.g, c.b, c.r+30, c.g+15, c.b-10))
	}

	fmt.Fprint(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "%s%s%s  %sADVANCED WEB SECURITY SCANNER%s  %sv%s%s\n",
		bLavender, "◆ AKCA", rst, cSlate, rst, cGhost, version, rst)
	fmt.Fprintf(os.Stderr, "%s%s%s\n\n", cGhost, strings.Repeat("─", uiWidth+4), rst)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  HELP — Panel-Based Usage Display
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func printUsage() {
	printBanner()

	panel := func(title string, entries []string) {
		fmt.Fprintln(os.Stderr, boxLine(boxTL, boxH, boxTR, uiWidth))
		fmt.Fprintln(os.Stderr, boxText(fmt.Sprintf(" %s◇%s  %s%s%s", cLavender, rst, bCloud, title, rst), uiWidth))
		fmt.Fprintln(os.Stderr, boxLine(boxML, boxH, boxMR, uiWidth))
		for _, entry := range entries {
			fmt.Fprintln(os.Stderr, boxText(entry, uiWidth))
		}
		fmt.Fprintln(os.Stderr, boxLine(boxBL, boxH, boxBR, uiWidth))
		fmt.Fprintln(os.Stderr)
	}

	panel("USAGE", []string{
		fmt.Sprintf("  %sakca%s %s-u%s <target> %s[options]%s", bCloud, rst, cIce, rst, cSlate, rst),
		fmt.Sprintf("  %sakca%s <target> %s[options]%s", bCloud, rst, cSlate, rst),
	})

	panel("SCAN OPTIONS", []string{
		fmt.Sprintf("  %s-u, --url%s <target>       %sExact target host%s  %s(required)%s", cIce, rst, cSlate, rst, bRose, rst),
		fmt.Sprintf("  %s-c, --cookie%s <value>     %sSession Cookie header%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s-H, --header%s <value>     %sRepeatable Name: Value header%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s-p, --proxy%s <url>        %sHTTP/S proxy%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s-k, --insecure%s           %sSkip target TLS verification%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s--rate-limit%s <n>         %sRequests per second%s  %s[50]%s", cIce, rst, cSlate, rst, cGhost, rst),
		fmt.Sprintf("  %s--concurrency%s <n>        %sParallel workers%s  %s[48]%s", cIce, rst, cSlate, rst, cGhost, rst),
		fmt.Sprintf("  %s--scan-id%s <id>           %sStable scan id for CI/policy%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s--no-oast%s                %sDisable blind callback checks%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s--no-fuzzing%s             %sDisable path fuzzing%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s--no-js%s                  %sDisable JavaScript analysis%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s--api-spec%s <path>        %sImport OpenAPI/Postman/HAR/etc.%s", cIce, rst, cSlate, rst),
	})

	panel("OUTPUT & CONTROL", []string{
		fmt.Sprintf("  %s-o, --output%s <path>      %sReport path%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s-f, --format%s <type>      %shtml | json | csv | markdown | sarif%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s--oast-server%s <url>      %sInteractsh-compatible API%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s--oast-wait%s <seconds>    %sCallback drain time%s  %s[60]%s", cIce, rst, cSlate, rst, cGhost, rst),
		fmt.Sprintf("  %s--version%s                %sPrint version%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %s-h, --help%s               %sShow this screen%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %sreplay --finding%s <id>    %sReplay stored proof%s", cIce, rst, cSlate, rst),
		fmt.Sprintf("  %sbenchmark%s                %sRun observed parity benchmark%s", cIce, rst, cSlate, rst),
	})

	panel("EXAMPLES", []string{
		fmt.Sprintf("  %s$%s %sakca -u https://target.test%s", cGhost, rst, cIce, rst),
		fmt.Sprintf("  %s$%s %sakca -u target.test -p http://127.0.0.1:8080 -k%s", cGhost, rst, cIce, rst),
		fmt.Sprintf("  %s$%s %sakca -u target.test --rate-limit 5 -f json%s", cGhost, rst, cIce, rst),
	})
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SEVERITY BADGES — Unicode Badge System
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func severityBadge(sev string) string {
	switch sev {
	case "critical":
		return fmt.Sprintf("%s ◈ CRITICAL %s", bCoral, rst)
	case "high":
		return fmt.Sprintf("%s ◆ HIGH %s", bRose, rst)
	case "medium":
		return fmt.Sprintf("%s ◇ MEDIUM %s", bAmber, rst)
	case "low":
		return fmt.Sprintf("%s ○ LOW %s", bIce, rst)
	default:
		return fmt.Sprintf("%s · INFO %s", cSlate, rst)
	}
}

func severityDot(sev string) string {
	switch sev {
	case "critical":
		return cCoral + "●" + rst
	case "high":
		return cRose + "●" + rst
	case "medium":
		return cAmber + "●" + rst
	case "low":
		return cIce + "●" + rst
	default:
		return cSlate + "●" + rst
	}
}

func severityColor(sev string) string {
	switch sev {
	case "critical":
		return bCoral
	case "high":
		return bRose
	case "medium":
		return bAmber
	case "low":
		return bIce
	default:
		return cSlate
	}
}

func confidenceColor(conf string) string {
	switch strings.ToLower(conf) {
	case "confirmed":
		return bMint
	case "high", "highconfidence":
		return cMint
	case "potential":
		return cAmber
	case "needsmanualreview":
		return cIce
	default:
		return cSlate
	}
}

func findingStatus(confidence string) (glyph, label, color string, confirmed bool) {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "confirmed":
		return "◆", "CONFIRMED", bMint, true
	case "highconfidence":
		return "◇", "HIGH CONFIDENCE", cMint, false
	case "potential":
		return "◇", "CANDIDATE", cAmber, false
	case "needsmanualreview":
		return "◇", "MANUAL REVIEW", cIce, false
	default:
		return "◇", "DETECTED", cSlate, false
	}
}

func payloadFloat(payload map[string]interface{}, key string) float64 {
	value, ok := payload[key]
	if !ok {
		return 0
	}
	switch number := value.(type) {
	case float64:
		return number
	case float32:
		return float64(number)
	case int:
		return float64(number)
	case int64:
		return float64(number)
	case json.Number:
		parsed, _ := number.Float64()
		return parsed
	default:
		return 0
	}
}

func payloadBool(payload map[string]interface{}, key string) bool {
	value, _ := payload[key].(bool)
	return value
}

func findingProof(signal string, payload map[string]interface{}) string {
	if payloadBool(payload, "oast_confirmed") {
		return "Correlated OAST callback received"
	}
	if payloadBool(payload, "timing_confirmed") {
		return "Paired timing controls passed"
	}
	switch strings.ToLower(signal) {
	case "error_based":
		return "Database error fingerprint reproduced"
	case "boolean_differential", "boolean_length":
		return "Boolean true/false differential reproduced"
	case "union_signal", "stacked_differential":
		return "Typed SQL response differential reproduced"
	case "timing_differential", "stacked_timing", "delayed_timing_confirmed":
		return "Timing signal requires manual reproduction"
	default:
		return strings.ReplaceAll(strings.TrimSpace(signal), "_", " ")
	}
}

func sessionOASTStatus(payload map[string]interface{}) (string, string) {
	if payloadBool(payload, "oast_enabled") {
		return "READY", bMint
	}
	return "OFF", cGhost
}

func payloadTargets(payload map[string]interface{}) string {
	switch targets := payload["targets"].(type) {
	case []string:
		clean := make([]string, 0, len(targets))
		for _, target := range targets {
			if value := safeTerminalText(target); value != "" {
				clean = append(clean, value)
			}
		}
		if len(clean) > 0 {
			return strings.Join(clean, ", ")
		}
	case []interface{}:
		clean := make([]string, 0, len(targets))
		for _, target := range targets {
			if value := safeTerminalText(fmt.Sprint(target)); value != "" {
				clean = append(clean, value)
			}
		}
		if len(clean) > 0 {
			return strings.Join(clean, ", ")
		}
	case string:
		if value := safeTerminalText(targets); value != "" {
			return value
		}
	}
	return "unknown target"
}

func scanSessionPanel(payload map[string]interface{}) string {
	targets := truncateText(payloadTargets(payload), uiWidth-4)
	rate := payloadFloat(payload, "global_rate_limit")
	maxPages := payloadInt(payload, "max_pages")
	oastStatus, oastColor := sessionOASTStatus(payload)
	profile := safeTerminalText(fmt.Sprint(payload["scan_profile"]))
	if profile == "" || profile == "<nil>" {
		profile = safeTerminalText(fmt.Sprint(payload["scan_intensity"]))
	}
	if profile == "" || profile == "<nil>" {
		profile = "default"
	}
	profile = truncateText(profile, 20)

	var b strings.Builder
	b.WriteString(boxLine(boxTL, boxH, boxTR, uiWidth) + "\n")
	b.WriteString(boxText(fmt.Sprintf(" %s◉%s  %sSCAN SESSION%s   %sRUNNING%s",
		cMint, rst, bCloud, rst, bMint, rst), uiWidth) + "\n")
	b.WriteString(boxLine(boxML, boxH, boxMR, uiWidth) + "\n")
	b.WriteString(boxText(fmt.Sprintf(" %sTARGET%s  %s%s%s",
		cSlate, rst, cIce, targets, rst), uiWidth) + "\n")
	b.WriteString(boxText(fmt.Sprintf(" %s%s%s  %s•%s  %s%.0f req/s%s  %s•%s  %s%d pages%s  %s•%s  %sOAST %s%s",
		cFrost, profile, rst, cGhost, rst, cSilver, rate, rst,
		cGhost, rst, cSilver, maxPages, rst, cGhost, rst, oastColor, oastStatus, rst), uiWidth) + "\n")
	b.WriteString(boxLine(boxBL, boxH, boxBR, uiWidth) + "\n\n")
	return b.String()
}

func trafficAdjustmentText(payload map[string]interface{}) string {
	return fmt.Sprintf("Rate %v/s  Host %v/s  Workers %v/%v",
		payload["global_rate_limit"], payload["per_host_rate_limit"],
		payload["max_concurrency"], payload["per_host_concurrency"])
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  PHASE DISPLAY — Icons & Labels
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func phaseLabel(phase string) string {
	labels := map[string]string{
		"bootstrap":           "Initializing Scan Engine",
		"fingerprint":         "Technology & WAF Fingerprinting",
		"fingerprinting":      "Technology & WAF Fingerprinting",
		"learning_waf":        "WAF Learning & Calibration",
		"crawling":            "Deep Crawling Targets",
		"js_analysis":         "JavaScript Analysis",
		"parameter_discovery": "Hidden Parameter Discovery",
		"fuzzing":             "Directory & Path Fuzzing",
		"bypass403":           "403 Bypass Testing",
		"auth_bypass":         "403 Bypass Testing",
		"reflection":          "Reflection Analysis",
		"vuln_modules":        "Vulnerability Scanning",
		"vuln_modules_a":      "Injection Vulnerability Scanning",
		"vuln_modules_b":      "SSRF, LFI & XXE Scanning",
		"vuln_modules_c":      "Auth & API Security Scanning",
		"vuln_modules_d":      "Config & Exposure Scanning",
		"oast_drain":          "OAST Callback Collection",
		"report_generation":   "Generating Report",
	}
	if l, ok := labels[phase]; ok {
		return l
	}
	return safeTerminalText(phase)
}

func phaseIcon(phase string) string {
	icons := map[string]string{
		"bootstrap":           "◎",
		"fingerprint":         "⌁",
		"fingerprinting":      "⌁",
		"learning_waf":        "⛊",
		"crawling":            "⟁",
		"js_analysis":         "⌗",
		"parameter_discovery": "◇",
		"fuzzing":             "⚔",
		"bypass403":           "⛊",
		"auth_bypass":         "⛊",
		"reflection":          "◉",
		"vuln_modules":        "⚔",
		"vuln_modules_a":      "⟁",
		"vuln_modules_b":      "⌁",
		"vuln_modules_c":      "⛊",
		"vuln_modules_d":      "◎",
		"oast_drain":          "⊙",
		"report_generation":   "▤",
	}
	if i, ok := icons[phase]; ok {
		return i
	}
	return "▸"
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  PROGRESS BAR — Gradient Block Bar
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func progressBar(percent, width int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := (percent * width) / 100
	empty := width - filled

	var sb strings.Builder
	// Gradient fill: lavender → mint
	for i := 0; i < filled; i++ {
		t := float64(i) / float64(max(width-1, 1))
		r := int(180 - t*80)
		g := int(167 + t*43)
		b := int(214 - t*34)
		sb.WriteString(fmt.Sprintf("\033[38;2;%d;%d;%dm█", r, g, b))
	}
	// Empty portion
	for i := 0; i < empty; i++ {
		sb.WriteString(fmt.Sprintf("%s░", cGhost))
	}
	sb.WriteString(rst)
	return sb.String()
}

// Mini inline bar for health snapshots
func miniBar(value, maxVal, width int) string {
	if maxVal <= 0 {
		maxVal = 1
	}
	percent := (value * 100) / maxVal
	if percent > 100 {
		percent = 100
	}
	filled := (percent * width) / 100
	empty := width - filled
	return cMint + strings.Repeat("▰", filled) + cGhost + strings.Repeat("▱", empty) + rst
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SLICE FLAG — Repeatable -H headers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

type sliceFlag []string

func (s *sliceFlag) String() string { return strings.Join(*s, ", ") }
func (s *sliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  CONSOLE WRITER — Event-Driven Display Engine
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

type ConsoleWriter struct {
	mu                  sync.Mutex
	detected            int
	verified            int
	severityMap         map[string]int
	startTime           time.Time
	lastPhase           string
	lastFinished        string
	lastProgress        string
	maxDiscovered       int
	maxTested           int
	lastDiscoveredPrint int
	lastTestedPrint     int
	lastSnapshot        time.Time
	lastTraffic         string
	mode                string
	requests            int
	forms               int
	oastProbes          int
	oastCallbacks       int
	wafBlocks           int
	coverageGaps        int
	suppressed          int
	progressLineOpen    bool
	phaseIndex          int
	phaseStarted        map[string]time.Time
}

func NewConsoleWriter() *ConsoleWriter {
	return NewConsoleWriterMode("normal")
}

func NewConsoleWriterMode(mode string) *ConsoleWriter {
	return &ConsoleWriter{
		severityMap:  make(map[string]int),
		phaseStarted: make(map[string]time.Time),
		startTime:    time.Now(),
		lastSnapshot: time.Now().Add(-10 * time.Second),
		mode:         mode,
	}
}

func quietEvent(eventType string) bool {
	switch eventType {
	case "scan_started", "scan_finished", "scan_stopped", "scan_error",
		"finding_detected", "finding_verified", "crawler_finished",
		"oast_started", "oast_failed", "oast_probe_failed", "oast_callback_received",
		"waf_detected", "waf_traffic_adjusted", "coverage_gap":
		return true
	default:
		return false
	}
}

func payloadInt(payload map[string]interface{}, key string) int {
	value, ok := payload[key]
	if !ok {
		return 0
	}
	switch number := value.(type) {
	case int:
		return number
	case int64:
		return int(number)
	case float64:
		return int(number)
	case json.Number:
		parsed, _ := number.Int64()
		return int(parsed)
	default:
		return 0
	}
}

func (cw *ConsoleWriter) WriteEvent(e events.Event) error {
	if e.Type == "event_batch" {
		if payload, ok := e.Payload["events"]; ok {
			b, err := json.Marshal(payload)
			if err == nil {
				var evs []events.Event
				if json.Unmarshal(b, &evs) == nil {
					for _, ev := range evs {
						_ = cw.handleEvent(ev)
					}
				}
			}
		}
		return nil
	}
	return cw.handleEvent(e)
}

func (cw *ConsoleWriter) elapsed() string {
	d := time.Since(cw.startTime)
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

func (cw *ConsoleWriter) acceptTrafficUpdate(text string) bool {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if cw.lastTraffic == text {
		return false
	}
	cw.lastTraffic = text
	return true
}

func shortDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

func (cw *ConsoleWriter) closeProgressLine() {
	cw.mu.Lock()
	open := cw.progressLineOpen
	cw.progressLineOpen = false
	cw.mu.Unlock()
	if open {
		fmt.Fprint(os.Stderr, "\n")
	}
}

func (cw *ConsoleWriter) writeProgressLine(line string) {
	if !isTTY() {
		fmt.Fprintln(os.Stderr, line)
		return
	}
	cw.mu.Lock()
	cw.progressLineOpen = true
	cw.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\r\033[K%s", line)
}

func (cw *ConsoleWriter) handleEvent(e events.Event) error {
	if cw.mode == "quiet" && !quietEvent(e.Type) {
		return nil
	}
	if e.Type != "health_snapshot" && e.Type != "report_generation_progress" {
		cw.closeProgressLine()
	}
	switch e.Type {

	// ── Log messages ────────────────────────────────────────────────────
	case "log":
		if cw.mode != "verbose" {
			return nil
		}
		msg := safeTerminalText(e.Message)
		if strings.Contains(msg, "engine booted") || strings.Contains(msg, "core engine") {
			return nil
		}
		fmt.Fprintf(os.Stderr, "%s%s%s %s%s%s\n",
			cGhost, "╎", rst, cSlate, msg, rst)

	// ── Scan lifecycle ──────────────────────────────────────────────────
	case "scan_started":
		fmt.Fprint(os.Stderr, scanSessionPanel(e.Payload))

	case "scan_finished":
		fmt.Fprintf(os.Stderr, "\n%s◉%s  %sScan complete%s  %s◷ %s%s\n",
			cMint, rst, bMint, rst, cSlate, cw.elapsed(), rst)

	case "scan_stopped":
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "%s◈%s  %sScan Aborted by User%s\n",
			cAmber, rst, bAmber, rst)

	case "scan_error":
		fmt.Fprintf(os.Stderr, "%s✖%s  %s%s%s\n",
			cRose, rst, cRose, safeTerminalText(e.Message), rst)

	// ── Phase transitions ───────────────────────────────────────────────
	case "phase_started":
		phase := ""
		if p, ok := e.Payload["phase"].(string); ok {
			phase = p
		}
		if _, ok := e.Payload["skipped"]; ok {
			return nil
		}
		cw.mu.Lock()
		if cw.lastPhase == phase {
			cw.mu.Unlock()
			return nil
		}
		cw.lastPhase = phase
		cw.phaseIndex++
		phaseIndex := cw.phaseIndex
		cw.phaseStarted[phase] = time.Now()
		cw.mu.Unlock()

		label := phaseLabel(phase)
		icon := phaseIcon(phase)

		fmt.Fprintf(os.Stderr, "%s%02d%s  %s%s%s  %s%s%s  %sRUNNING%s\n",
			cGhost, phaseIndex, rst, cTeal, icon, rst, bCloud, label, rst, cTeal, rst)

	case "phase_finished":
		if _, ok := e.Payload["skipped"]; ok {
			return nil
		}
		phase := ""
		if p, ok := e.Payload["phase"].(string); ok {
			phase = p
		}
		cw.mu.Lock()
		if cw.lastFinished == phase {
			cw.mu.Unlock()
			return nil
		}
		cw.lastFinished = phase
		started := cw.phaseStarted[phase]
		cw.mu.Unlock()

		duration := ""
		if !started.IsZero() {
			duration = fmt.Sprintf("  %s%s%s", cGhost, shortDuration(time.Since(started)), rst)
		}
		fmt.Fprintf(os.Stderr, "    %s╰─%s %s✓ COMPLETE%s%s\n",
			cGhost, rst, cMint, rst, duration)

	// ── Progress messages ───────────────────────────────────────────────
	case "scan_progress":
		msg := safeTerminalText(e.Message)
		if msg == "" || msg == "crawling" || msg == "fuzzing" || msg == "fingerprinting" || msg == "bypass403" || msg == "reflection" {
			return nil
		}
		cw.mu.Lock()
		if cw.lastProgress == msg {
			cw.mu.Unlock()
			return nil
		}
		cw.lastProgress = msg
		cw.mu.Unlock()
		fmt.Fprintf(os.Stderr, "%s⟳%s  %s%s%s\n",
			cLavender, rst, cSlate, msg, rst)

	// ── Vulnerability detection ─────────────────────────────────────────
	case "finding_detected":
		title, _ := e.Payload["title"].(string)
		severity, _ := e.Payload["severity"].(string)
		endpoint, _ := e.Payload["endpoint_url"].(string)
		vulnClass, _ := e.Payload["vuln_class"].(string)
		signalVal, _ := e.Payload["signal"].(string)
		method, _ := e.Payload["method"].(string)
		payloadStr, _ := e.Payload["payload_str"].(string)
		parameter, _ := e.Payload["parameter"].(string)
		location, _ := e.Payload["location"].(string)
		confidence, _ := e.Payload["confidence"].(string)
		score := payloadFloat(e.Payload, "score")
		title = safeTerminalText(title)
		endpoint = safeTerminalText(endpoint)
		vulnClass = safeTerminalText(vulnClass)
		signalVal = safeTerminalText(signalVal)
		method = safeTerminalText(method)
		payloadStr = safeTerminalText(payloadStr)
		parameter = safeTerminalText(parameter)
		location = safeTerminalText(location)
		confidence = safeTerminalText(confidence)
		if score < 0 {
			score = 0
		} else if score > 1 {
			score = 1
		}
		statusGlyph, statusLabel, statusCol, confirmed := findingStatus(confidence)

		cw.mu.Lock()
		cw.detected++
		sev := strings.ToLower(severity)
		cw.severityMap[sev]++
		if confirmed {
			cw.verified++
		}
		cw.mu.Unlock()

		sevCol := severityColor(sev)

		// ── Finding card with box drawing ──
		findingName := vulnClass
		if findingName == "" {
			findingName = title
		}
		if parameter != "" {
			findingName += " on " + parameter
		}
		fmt.Fprintf(os.Stderr, "\n%s%s %s%s  %s%s%s  %s%s %.2f%s\n",
			statusCol, statusGlyph, statusLabel, rst, bCloud, findingName, rst,
			confidenceColor(confidence), confidence, score, rst)
		cardW := uiWidth + 2
		fmt.Fprintf(os.Stderr, "%s%s%s%s%s\n",
			sevCol, boxTL, strings.Repeat(boxH, cardW), boxTR, rst)

		// Badge + title line
		badge := severityBadge(sev)
		title = truncateText(title, max(1, cardW-visibleLen(badge)-3))
		titleLine := fmt.Sprintf(" %s  %s%s%s", badge, bCloud, title, rst)
		fmt.Fprintf(os.Stderr, "%s%s%s%s%s%s%s\n",
			sevCol, boxV, rst, padToWidth(titleLine, cardW), sevCol, boxV, rst)

		fmt.Fprintf(os.Stderr, "%s%s%s%s%s\n",
			sevCol, boxML, strings.Repeat(boxH, cardW), boxMR, rst)

		// Detail lines with tree connectors
		type detailLine struct {
			label string
			value string
			color string
		}
		var details []detailLine
		details = append(details, detailLine{"Status", fmt.Sprintf("%s · %.2f", statusLabel, score), statusCol})
		if vulnClass != "" {
			details = append(details, detailLine{"Class", formatVulnType(vulnClass, signalVal), cSilver})
		}
		if endpoint != "" {
			details = append(details, detailLine{"URL", endpoint, cIce})
		}
		if parameter != "" {
			details = append(details, detailLine{"Param", parameter, cFrost})
		}
		if location != "" {
			details = append(details, detailLine{"Location", strings.ToUpper(location), cSilver})
		}
		if method != "" {
			details = append(details, detailLine{"Method", strings.ToUpper(method), cSilver})
		}
		responseStatus := payloadInt(e.Payload, "response_status")
		responseDuration := payloadInt(e.Payload, "response_duration_ms")
		if responseStatus > 0 {
			httpValue := fmt.Sprintf("HTTP %d", responseStatus)
			if responseDuration > 0 {
				httpValue += fmt.Sprintf(" · %dms", responseDuration)
			}
			details = append(details, detailLine{"Response", httpValue, cSilver})
		}
		if proof := safeTerminalText(findingProof(signalVal, e.Payload)); proof != "" {
			details = append(details, detailLine{"Proof", proof, statusCol})
		}
		if payloadStr != "" {
			details = append(details, detailLine{"Payload", payloadStr, cFrost})
		}

		for i, d := range details {
			connector := cGhost + "├─" + rst
			if i == len(details)-1 {
				connector = cGhost + "╰─" + rst
			}
			label := fmt.Sprintf("%s%s%s", cSlate, d.label, rst)
			valueWidth := cardW - visibleLen(fmt.Sprintf(" %s %s ", connector, label))
			value := fmt.Sprintf("%s%s%s", d.color, truncateText(d.value, max(1, valueWidth)), rst)
			innerLine := fmt.Sprintf(" %s %s %s", connector, label, value)
			fmt.Fprintf(os.Stderr, "%s%s%s%s%s%s%s\n",
				sevCol, boxV, rst, padToWidth(innerLine, cardW), sevCol, boxV, rst)
		}

		fmt.Fprintf(os.Stderr, "%s%s%s%s%s\n",
			sevCol, boxBL, strings.Repeat(boxH, cardW), boxBR, rst)

	// ── Verified finding ────────────────────────────────────────────────
	case "finding_verified":
		suppressed, _ := e.Payload["suppressed"].(bool)

		if suppressed {
			cw.mu.Lock()
			cw.suppressed++
			cw.mu.Unlock()
			return nil
		}

		// Render only after finding_detected supplies the request, response and
		// proof context. This prevents a manual-review result from appearing as
		// an isolated VERIFIED line.
		return nil

	// ── Crawler events ──────────────────────────────────────────────────
	case "crawler_started":
		fmt.Fprintf(os.Stderr, "%s⟳%s  %sCrawler active...%s\n",
			cLavender, rst, cSlate, rst)

	case "crawler_finished":
		pages := 0
		if p, ok := e.Payload["pages"].(float64); ok {
			pages = int(p)
		} else if p, ok := e.Payload["pages_crawled"].(float64); ok {
			pages = int(p)
		}
		cw.mu.Lock()
		cw.requests = payloadInt(e.Payload, "requests")
		cw.mu.Unlock()
		fmt.Fprintf(os.Stderr, "%s✓%s  %sCrawler finished%s %s— %d pages%s\n",
			cMint, rst, cSilver, rst, cSlate, pages, rst)

	// ── Health snapshots ────────────────────────────────────────────────
	case "oast_started":
		// OAST readiness is shown once in the scan session card. The provider
		// domain is intentionally omitted from normal mode because it is long,
		// transient and previously duplicated the same state above the card.
		if cw.mode == "verbose" {
			fmt.Fprintf(os.Stderr, "%s╎%s  %sOAST provider%s  %s%s%s\n",
				cGhost, rst, cSlate, rst, cSilver,
				safeTerminalText(fmt.Sprint(e.Payload["mode"])), rst)
		}

	case "oast_failed":
		fmt.Fprintf(os.Stderr, "%s[OAST FAILED]%s  %s%s%s\n", bRose, rst, cRose, safeTerminalText(e.Message), rst)

	case "oast_probe_sent":
		cw.mu.Lock()
		cw.oastProbes++
		cw.mu.Unlock()
		if cw.mode == "verbose" {
			fmt.Fprintf(os.Stderr, "%s[OAST SENT]%s  %s%s %s%s%s\n", cTeal, rst, cSilver,
				safeTerminalText(fmt.Sprint(e.Payload["method"])), cIce,
				safeTerminalText(fmt.Sprint(e.Payload["endpoint"])), rst)
		}

	case "oast_probe_failed":
		method := safeTerminalText(fmt.Sprint(e.Payload["method"]))
		endpoint := safeTerminalText(fmt.Sprint(e.Payload["endpoint"]))
		if method == "<nil>" {
			method = ""
		}
		if endpoint == "<nil>" {
			endpoint = ""
		}
		deliveryTarget := strings.TrimSpace(strings.Join([]string{method, endpoint}, " "))
		if deliveryTarget != "" {
			deliveryTarget += " — "
		}
		fmt.Fprintf(os.Stderr, "%s[OAST DELIVERY GAP]%s  %s%s%s%s\n",
			bAmber, rst, cAmber, deliveryTarget, safeTerminalText(e.Message), rst)

	case "oast_callback_received":
		cw.mu.Lock()
		cw.oastCallbacks++
		cw.mu.Unlock()
		fmt.Fprintf(os.Stderr, "%s[OAST HIT]%s  %s%s%s  %sCONFIRMED%s\n", bMint, rst, cIce,
			safeTerminalText(fmt.Sprint(e.Payload["endpoint"])), rst, bMint, rst)

	case "waf_detected":
		fmt.Fprintf(os.Stderr, "%s[WAF]%s  %s%s%s\n",
			bAmber, rst, cSilver, safeTerminalText(e.Message), rst)

	case "waf_traffic_adjusted":
		trafficText := trafficAdjustmentText(e.Payload)
		if !cw.acceptTrafficUpdate(trafficText) {
			return nil
		}
		fmt.Fprintf(os.Stderr, "%s[TRAFFIC]%s  %s%s%s\n",
			bAmber, rst, cAmber, trafficText, rst)

	case "coverage_gap":
		cw.mu.Lock()
		cw.coverageGaps++
		cw.mu.Unlock()
		fmt.Fprintf(os.Stderr, "%s[COVERAGE]%s  %s%s%s\n", bAmber, rst, cAmber, safeTerminalText(e.Message), rst)

	case "plugin_skipped":
		if cw.mode == "verbose" {
			fmt.Fprintf(os.Stderr, "%s[SKIP]%s  %s%s%s  %s%s%s\n", cGhost, rst, cSilver,
				safeTerminalText(fmt.Sprint(e.Payload["module"])), rst, cSlate, safeTerminalText(e.Message), rst)
		}

	case "health_snapshot":
		rate, _ := e.Payload["request_rate"].(float64)
		discoveredVal, _ := e.Payload["endpoints_discovered"].(float64)
		testedVal, _ := e.Payload["endpoints_tested"].(float64)
		discovered := int(discoveredVal)
		tested := int(testedVal)

		cw.mu.Lock()
		if discovered > cw.maxDiscovered {
			cw.maxDiscovered = discovered
		} else {
			discovered = cw.maxDiscovered
		}
		if tested > cw.maxTested {
			cw.maxTested = tested
		} else {
			tested = cw.maxTested
		}

		if discovered == cw.lastDiscoveredPrint && tested == cw.lastTestedPrint {
			cw.mu.Unlock()
			return nil
		}
		cw.lastDiscoveredPrint = discovered
		cw.lastTestedPrint = tested

		now := time.Now()
		if now.Sub(cw.lastSnapshot) < 10*time.Second {
			cw.mu.Unlock()
			return nil
		}
		cw.lastSnapshot = now
		cw.mu.Unlock()

		if rate > 0 || discovered > 0 {
			bar := miniBar(tested, max(discovered, 1), 12)
			line := fmt.Sprintf("%s⊡%s  %s%.1f%s req/s  %s%d%s endpoints  %s  %s%d%s tested",
				cSky, rst, cSky, rate, rst, cSilver, discovered, rst, bar, cMint, tested, rst)
			cw.writeProgressLine(line)
		}

	// ── Report progress ─────────────────────────────────────────────────
	case "report_generation_progress":
		percent, _ := e.Payload["percent"].(float64)
		section, _ := e.Payload["section"].(string)
		bar := progressBar(int(percent), 20)
		line := fmt.Sprintf("%s⟳%s  Report: %s %s%.0f%%%s %s%s%s",
			cLavender, rst, bar, bCloud, percent, rst, cSlate, safeTerminalText(section), rst)
		cw.writeProgressLine(line)
	}

	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SUMMARY DASHBOARD — Post-Scan Mini Dashboard
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func printSummary(cw *ConsoleWriter, outPath string) {
	cw.closeProgressLine()
	cw.mu.Lock()
	det := cw.detected
	ver := cw.verified
	suppressed := cw.suppressed
	requests := cw.requests
	oastCallbacks := cw.oastCallbacks
	sev := make(map[string]int)
	for k, v := range cw.severityMap {
		sev[k] = v
	}
	elapsed := cw.elapsed()
	cw.mu.Unlock()

	w := uiWidth + 2

	fmt.Fprint(os.Stderr, "\n")

	// ── Top border (double line) ──
	fmt.Fprintf(os.Stderr, "%s%s%s%s%s\n",
		cLavender, dBoxTL, strings.Repeat(dBoxH, w), dBoxTR, rst)

	// ── Title ──
	titleLine := fmt.Sprintf(" %s◆%s  %sSCAN RESULT%s%s%sNEON PULSE / v%s%s",
		cMint, rst, bCloud, rst, strings.Repeat(" ", 25), cGhost, version, rst)
	fmt.Fprintf(os.Stderr, "%s%s%s%s%s%s%s\n",
		cLavender, dBoxV, rst, padToWidth(titleLine, w), cLavender, dBoxV, rst)

	// ── Separator ──
	fmt.Fprintf(os.Stderr, "%s%s%s%s%s\n",
		cLavender, "╠", strings.Repeat(dBoxH, w), "╣", rst)

	// ── Metric rows ──
	printMetric := func(icon, label, value string) {
		line := fmt.Sprintf(" %s  %s%s%s  %s", icon, cSlate, label, rst, value)
		fmt.Fprintf(os.Stderr, "%s%s%s%s%s%s%s\n",
			cLavender, dBoxV, rst, padToWidth(line, w), cLavender, dBoxV, rst)
	}

	printMetric(cSlate+"◷"+rst, "Duration", fmt.Sprintf("%s%s%s", bCloud, elapsed, rst))
	printMetric(cLavender+"◈"+rst, "Detected", fmt.Sprintf("%s%d%s", bCloud, det, rst))
	printMetric(cMint+"◆"+rst, "Confirmed", fmt.Sprintf("%s%d%s", bMint, ver, rst))
	printMetric(cGhost+"◇"+rst, "Suppressed", fmt.Sprintf("%s%d%s", cSlate, suppressed, rst))
	printMetric(cIce+"⌁"+rst, "Traffic", fmt.Sprintf("%s%d requests%s  %s·%s  %s%d OAST hits%s",
		cSilver, requests, rst, cGhost, rst, cMint, oastCallbacks, rst))

	// ── Separator ──
	fmt.Fprintf(os.Stderr, "%s%s%s%s%s\n",
		cLavender, "╠", strings.Repeat(dBoxH, w), "╣", rst)

	if det > 0 {
		crit := sev["critical"]
		high := sev["high"]
		med := sev["medium"]
		low := sev["low"]
		info := sev["info"]
		total := max(det, 1)

		// Severity distribution with bar visualization
		type sevEntry struct {
			name  string
			count int
			color string
			dot   string
		}
		entries := []sevEntry{
			{"Critical", crit, cCoral, "●"},
			{"High", high, cRose, "●"},
			{"Medium", med, cAmber, "●"},
			{"Low", low, cIce, "●"},
			{"Info", info, cSlate, "●"},
		}

		for _, entry := range entries {
			if entry.count == 0 {
				continue
			}
			barWidth := (entry.count * 20) / total
			if barWidth < 1 && entry.count > 0 {
				barWidth = 1
			}
			bar := entry.color + strings.Repeat("█", barWidth) + rst + cGhost + strings.Repeat("░", 20-barWidth) + rst

			line := fmt.Sprintf(" %s%s%s %-8s %s %s%d%s",
				entry.color, entry.dot, rst, entry.name, bar, entry.color, entry.count, rst)
			fmt.Fprintf(os.Stderr, "%s%s%s%s%s%s%s\n",
				cLavender, dBoxV, rst, padToWidth(line, w), cLavender, dBoxV, rst)
		}
	} else {
		noVulnLine := fmt.Sprintf(" %s✓%s  %sNo vulnerabilities detected%s", cMint, rst, cMint, rst)
		fmt.Fprintf(os.Stderr, "%s%s%s%s%s%s%s\n",
			cLavender, dBoxV, rst, padToWidth(noVulnLine, w), cLavender, dBoxV, rst)
	}

	// ── Report path ──
	fmt.Fprintf(os.Stderr, "%s%s%s%s%s\n",
		cLavender, "╠", strings.Repeat(dBoxH, w), "╣", rst)

	reportPath := truncateText(safeTerminalText(outPath), w-5)
	reportLine := fmt.Sprintf(" %s▤%s  %s%s%s", cSlate, rst, cIce, reportPath, rst)
	fmt.Fprintf(os.Stderr, "%s%s%s%s%s%s%s\n",
		cLavender, dBoxV, rst, padToWidth(reportLine, w), cLavender, dBoxV, rst)

	// ── Bottom border ──
	fmt.Fprintf(os.Stderr, "%s%s%s%s%s\n",
		cLavender, dBoxBL, strings.Repeat(dBoxH, w), dBoxBR, rst)
	fmt.Fprint(os.Stderr, "\n")
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  HELPER FUNCTIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func parseCookies(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && kv[0] != "" {
			out[kv[0]] = kv[1]
		}
	}
	return out
}

func parseHeaders(raw []string) (map[string]string, error) {
	out := map[string]string{}
	for i, h := range raw {
		kv := strings.SplitN(h, ":", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" {
			return nil, fmt.Errorf("invalid --header value at position %d; expected Name: Value", i+1)
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out, nil
}

func normalizeFormat(fmtStr string) (report.Format, error) {
	switch strings.ToLower(strings.TrimSpace(fmtStr)) {
	case "html":
		return report.FormatHTML, nil
	case "json":
		return report.FormatJSON, nil
	case "csv":
		return report.FormatCSV, nil
	case "markdown", "md":
		return report.FormatMarkdown, nil
	case "sarif":
		return report.FormatSARIF, nil
	default:
		return "", fmt.Errorf("unsupported format: %q", fmtStr)
	}
}

func printCLIError(err error) {
	fmt.Fprintf(os.Stderr, "\n   %s✖%s  %s%s%s\n", cRose, rst, bRose, safeTerminalText(err.Error()), rst)
	fmt.Fprintf(os.Stderr, "   %sRun '%sakca --help%s%s' for usage information.%s\n\n",
		cSlate, cIce, rst, cSlate, rst)
}

func formatVulnType(vulnClass, signal string) string {
	if signal == "" {
		return strings.ToUpper(vulnClass)
	}

	prettySignals := map[string]string{
		"reflected_html":       "Reflected HTML",
		"reflected_attribute":  "Reflected Attribute",
		"reflected_javascript": "Reflected JavaScript",
		"dom_xss":              "DOM-Based",
		"blind_xss":            "Blind",
		"time_blind":           "Time-Based Blind",
		"boolean_blind":        "Boolean-Based Blind",
		"error_based":          "Error-Based",
		"dns_callback":         "DNS Callback",
		"http_callback":        "HTTP Callback",
		"dns":                  "DNS Callback",
		"http":                 "HTTP Callback",
		"origin_reflection":    "Origin Reflection",
		"wildcard_credentials": "Wildcard With Credentials",
		"null_origin":          "Null Origin Reflection",
		"path_fuzz":            "Path Manipulation",
		"header_fuzz":          "HTTP Headers Manipulation",
		"method_override":      "HTTP Method Override",
	}

	if pretty, ok := prettySignals[strings.ToLower(signal)]; ok {
		return fmt.Sprintf("%s (%s)", strings.ToUpper(vulnClass), pretty)
	}

	// Fallback to Title Cased signal
	words := strings.Split(strings.ReplaceAll(signal, "_", " "), " ")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return fmt.Sprintf("%s (%s)", strings.ToUpper(vulnClass), strings.Join(words, " "))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  MAIN — Entry Point
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func main() {
	if len(os.Args) > 1 && os.Args[1] == "replay" {
		os.Exit(runReplayCommand(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "benchmark" {
		os.Exit(runBenchmarkCommand(os.Args[2:]))
	}
	var targetURL string
	var proxyURL string
	var insecureTLS bool
	var cookieVal string
	var headers sliceFlag
	var apiSpecs sliceFlag
	var outputFormat string
	var outputFilePath string
	var noOAST bool
	var oastServer string
	var oastWait int
	var noFuzzing bool
	var noJS bool
	var rateLimit float64
	var concurrency int
	var showVersion bool
	var showHelp bool
	var scanID string

	fs := flag.NewFlagSet("akca", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&targetURL, "url", "", "")
	fs.StringVar(&targetURL, "u", "", "")
	fs.StringVar(&proxyURL, "proxy", "", "")
	fs.StringVar(&proxyURL, "p", "", "")
	fs.BoolVar(&insecureTLS, "insecure", false, "")
	fs.BoolVar(&insecureTLS, "k", false, "")
	fs.StringVar(&cookieVal, "cookie", "", "")
	fs.StringVar(&cookieVal, "c", "", "")
	fs.Var(&headers, "header", "")
	fs.Var(&headers, "H", "")
	fs.Var(&apiSpecs, "api-spec", "")
	fs.StringVar(&outputFormat, "format", "html", "")
	fs.StringVar(&outputFormat, "f", "html", "")
	fs.StringVar(&outputFilePath, "output", "", "")
	fs.StringVar(&outputFilePath, "o", "", "")
	fs.BoolVar(&noOAST, "no-oast", false, "")
	fs.StringVar(&oastServer, "oast-server", "", "")
	fs.IntVar(&oastWait, "oast-wait", 60, "")
	fs.BoolVar(&noFuzzing, "no-fuzzing", false, "")
	fs.BoolVar(&noJS, "no-js", false, "")
	fs.Float64Var(&rateLimit, "rate-limit", 50, "")
	fs.IntVar(&concurrency, "concurrency", 48, "")
	fs.StringVar(&scanID, "scan-id", "", "")
	fs.BoolVar(&showVersion, "version", false, "")
	fs.BoolVar(&showHelp, "help", false, "")
	fs.BoolVar(&showHelp, "h", false, "")

	// Parsing errors are rendered below with Neon Pulse semantics. Keeping the
	// FlagSet usage hook silent prevents an unknown flag from dumping the full
	// help screen before the concise error.
	fs.Usage = func() {}
	if err := fs.Parse(os.Args[1:]); err != nil {
		printCLIError(err)
		os.Exit(2)
	}

	if showVersion {
		fmt.Printf("%sakca%s %sv%s%s\n", bLavender, rst, cSlate, version, rst)
		os.Exit(0)
	}

	if showHelp || (targetURL == "" && fs.NArg() == 0) {
		printUsage()
		os.Exit(0)
	}

	// Allow positional argument: akca domain.com
	if targetURL == "" && fs.NArg() > 0 {
		targetURL = fs.Arg(0)
		if fs.NArg() > 1 {
			printCLIError(fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args()[1:], " ")))
			os.Exit(2)
		}
	} else if fs.NArg() > 0 {
		printCLIError(fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " ")))
		os.Exit(2)
	}
	targetURL = strings.TrimSpace(targetURL)

	if targetURL == "" {
		printCLIError(fmt.Errorf("target URL is required"))
		os.Exit(1)
	}
	if rateLimit <= 0 || math.IsNaN(rateLimit) || math.IsInf(rateLimit, 0) {
		printCLIError(fmt.Errorf("--rate-limit must be greater than zero"))
		os.Exit(2)
	}
	if concurrency <= 0 {
		printCLIError(fmt.Errorf("--concurrency must be greater than zero"))
		os.Exit(2)
	}
	if oastWait < 0 {
		printCLIError(fmt.Errorf("--oast-wait cannot be negative"))
		os.Exit(2)
	}
	customHeaders, err := parseHeaders(headers)
	if err != nil {
		printCLIError(err)
		os.Exit(2)
	}

	repFmt, err := normalizeFormat(outputFormat)
	if err != nil {
		printCLIError(err)
		os.Exit(1)
	}

	printBanner()

	// ── Bootstrap data directory ────────────────────────────────────────
	if _, err := storage.BootstrapDataDir(); err != nil {
		fmt.Fprintf(os.Stderr, "   %s✖%s  %sData directory error: %v%s\n",
			cRose, rst, cRose, err, rst)
	}
	if browserPath, downloaded, err := browserpool.EnsureBrowser(); err != nil {
		fmt.Fprintf(os.Stderr, "   %s△%s  %sBrowser automation unavailable: %v%s\n",
			cAmber, rst, cAmber, err, rst)
		fmt.Fprintf(os.Stderr, "      %sContinuing with HTTP coverage; DOM execution checks will be skipped.%s\n",
			cSlate, rst)
	} else if downloaded {
		fmt.Fprintf(os.Stderr, "   %s✓%s  %sChromium installed automatically%s  %s%s%s\n",
			cMint, rst, cSilver, rst, cGhost, safeTerminalText(browserPath), rst)
	}

	// ── Create engine ───────────────────────────────────────────────────
	cw := NewConsoleWriter()
	engine, err := app.New(cw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n   %s✖%s  %sEngine initialization failed: %v%s\n\n",
			cRose, rst, bRose, err, rst)
		os.Exit(1)
	}
	defer engine.Close()

	// ── Build scan config ───────────────────────────────────────────────
	cfg := config.DefaultScanConfig()
	cfg.ScanID = strings.TrimSpace(scanID)
	if cfg.ScanID == "" {
		cfg.ScanID = fmt.Sprintf("scan-%d", time.Now().Unix())
	}
	cfg.Targets = []string{targetURL}
	cfg.APIImportFiles = append([]string(nil), apiSpecs...)
	cfg.SmartScanProfile = "FullBugBounty"
	cfg.SkipAutoReport = true

	if proxyURL != "" {
		cfg.ProxyURL = strings.TrimSpace(proxyURL)
	}
	cfg.InsecureSkipVerify = insecureTLS
	if cookieVal != "" {
		cfg.SessionCookies = parseCookies(cookieVal)
	}
	if len(customHeaders) > 0 {
		cfg.CustomHeaders = customHeaders
	}
	cfg.EnableOAST = !noOAST
	if strings.TrimSpace(oastServer) != "" {
		cfg.OASTServerURL = strings.TrimSpace(oastServer)
	}
	cfg.OASTDrainTimeout = time.Duration(oastWait) * time.Second
	cfg.EnableFuzzing = !noFuzzing
	cfg.EnableJSAnalysis = !noJS
	if noOAST {
		cfg.Explicit.EnableOAST = true
	}
	if noFuzzing {
		cfg.Explicit.EnableFuzzing = true
	}
	if noJS {
		cfg.Explicit.EnableJSAnalysis = true
	}
	if rateLimit > 0 {
		cfg.GlobalRateLimit = rateLimit
		cfg.Explicit.GlobalRateLimit = true
	}
	if concurrency > 0 {
		cfg.MaxConcurrency = concurrency
		cfg.Explicit.MaxConcurrency = true
	}

	// ── Start scan ──────────────────────────────────────────────────────
	if err := engine.StartScan(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\n   %s✖%s  %sScan failed to start: %v%s\n\n",
			cRose, rst, bRose, err, rst)
		os.Exit(1)
	}

	// ── Graceful shutdown on SIGINT/SIGTERM ──────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cw.closeProgressLine()
		fmt.Fprintf(os.Stderr, "   %s△%s  %sInterrupt received — stopping gracefully...%s\n",
			cAmber, rst, bAmber, rst)
		_ = engine.StopScan()
		cancel()
	}()

	// ── Wait for scan completion ────────────────────────────────────────
	if err := engine.WaitScanDone(ctx); err != nil && err != context.Canceled {
		cw.closeProgressLine()
		fmt.Fprintf(os.Stderr, "   %s✖%s  %sScan error: %v%s\n",
			cRose, rst, cRose, err, rst)
	}

	// ── Generate report ─────────────────────────────────────────────────
	cw.closeProgressLine()
	fmt.Fprintf(os.Stderr, "\n   %s⟳%s  %sGenerating %s report...%s\n",
		cLavender, rst, cSlate, string(repFmt), rst)

	reportOpts := report.Options{
		ScanID:   cfg.ScanID,
		Template: report.TemplateInternal,
		Format:   repFmt,
		Partial:  false,
		Redact:   false,
	}

	reportData, err := engine.GenerateReport(reportOpts)
	if err != nil {
		cw.closeProgressLine()
		fmt.Fprintf(os.Stderr, "   %s✖%s  %sReport generation failed: %v%s\n",
			cRose, rst, bRose, err, rst)
		os.Exit(1)
	}

	outPath := outputFilePath
	if outPath == "" {
		ext := string(repFmt)
		if repFmt == report.FormatMarkdown {
			ext = "md"
		}
		outPath = fmt.Sprintf("akca-report-%s.%s", cfg.ScanID, ext)
	}

	if err := os.WriteFile(outPath, reportData, 0o644); err != nil {
		cw.closeProgressLine()
		fmt.Fprintf(os.Stderr, "   %s✖%s  %sFailed to save report: %v%s\n",
			cRose, rst, bRose, err, rst)
		os.Exit(1)
	}

	// ── Print summary ───────────────────────────────────────────────────
	cw.closeProgressLine()
	printSummary(cw, outPath)
}

func runReplayCommand(args []string) int {
	fs := flag.NewFlagSet("akca replay", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var findingID int64
	fs.Int64Var(&findingID, "finding", 0, "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "akca replay: %v\n", err)
		return 2
	}
	if findingID <= 0 || fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: akca replay --finding <id>")
		return 2
	}
	if _, err := storage.BootstrapDataDir(); err != nil {
		fmt.Fprintf(os.Stderr, "akca replay: %v\n", err)
		return 1
	}
	engine, err := app.New(NewConsoleWriter())
	if err != nil {
		fmt.Fprintf(os.Stderr, "akca replay: %v\n", err)
		return 1
	}
	defer engine.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	result, err := engine.ReplayFinding(ctx, findingID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "akca replay: %v\n", err)
		return 1
	}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(encoded))
	if result.Status == "inconclusive" {
		return 3
	}
	return 0
}

func runBenchmarkCommand(args []string) int {
	fs := flag.NewFlagSet("akca benchmark", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dbPath string
	var outputPath string
	var strict bool
	fs.StringVar(&dbPath, "db", "", "")
	fs.StringVar(&outputPath, "output", "", "")
	fs.BoolVar(&strict, "strict", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "akca benchmark: %v\n", err)
		}
		fmt.Fprintln(os.Stderr, "usage: akca benchmark [--db <path>] [--output <json>] [--strict]")
		return 2
	}
	if dbPath == "" {
		if _, err := storage.BootstrapDataDir(); err != nil {
			fmt.Fprintf(os.Stderr, "akca benchmark: %v\n", err)
			return 1
		}
		var err error
		dbPath, err = storage.DefaultDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "akca benchmark: %v\n", err)
			return 1
		}
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "akca benchmark: %v\n", err)
		return 1
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		fmt.Fprintf(os.Stderr, "akca benchmark: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	results, err := benchmark.NewLab(db).RunObserved(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "akca benchmark: %v\n", err)
		return 1
	}
	gate := benchmark.EvaluateQualityGate(
		benchmark.DefaultScenarios(), results, benchmark.StrictGateConfig(),
	)
	payload := map[string]interface{}{"results": results, "quality_gate": gate}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "akca benchmark: %v\n", err)
		return 1
	}
	if outputPath == "" {
		fmt.Println(string(encoded))
	} else if err := os.WriteFile(outputPath, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "akca benchmark: %v\n", err)
		return 1
	}
	if strict && !gate.Passed {
		return 3
	}
	return 0
}
