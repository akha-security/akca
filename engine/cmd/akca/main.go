package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/akha-security/akca/engine/internal/app"
	"github.com/akha-security/akca/engine/internal/benchmark"
	"github.com/akha-security/akca/engine/internal/branding"
	"github.com/akha-security/akca/engine/internal/browserpool"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/report"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/subdomain"
)

const (
	version    = branding.Version
	uiWidth    = 76
	minUIWidth = 56
	maxUIWidth = 92
)

// Terminal presentation uses a restrained 256-colour palette. Unlike the old
// per-character true-colour gradients, this renders consistently in Windows
// Terminal, common Unix terminals, tmux and remote shells.

const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiDim       = "\033[2m"
	ansiItalic    = "\033[3m"
	ansiUnderline = "\033[4m"

	ansiBlue   = "\033[38;5;75m"
	ansiGreen  = "\033[38;5;78m"
	ansiYellow = "\033[38;5;221m"
	ansiRed    = "\033[38;5;203m"
	ansiCyan   = "\033[38;5;81m"
	ansiOrange = "\033[38;5;209m"
	ansiText   = "\033[38;5;252m"
	ansiMuted  = "\033[38;5;245m"
	ansiFrame  = "\033[38;5;239m"
	ansiBright = "\033[38;5;255m"
	ansiPurple = "\033[38;5;141m"
)

var (
	rst = ansiReset
	bld = ansiBold
	dm  = ansiDim
	itl = ansiItalic
	ul  = ansiUnderline

	cLavender = ansiBlue
	cMint     = ansiGreen
	cAmber    = ansiYellow
	cRose     = ansiRed
	cIce      = ansiCyan
	cPeach    = ansiOrange
	cSilver   = ansiText
	cSlate    = ansiMuted
	cGhost    = ansiFrame
	cCloud    = ansiBright
	cLilac    = ansiPurple
	cTeal     = ansiCyan
	cSky      = ansiBlue
	cCoral    = ansiRed
	cFrost    = ansiCyan

	bLavender = ansiBold + ansiBlue
	bMint     = ansiBold + ansiGreen
	bAmber    = ansiBold + ansiYellow
	bRose     = ansiBold + ansiRed
	bIce      = ansiBold + ansiCyan
	bPeach    = ansiBold + ansiOrange
	bCloud    = ansiBold + ansiBright
	bLilac    = ansiBold + ansiPurple
	bTeal     = ansiBold + ansiCyan
	bCoral    = ansiBold + ansiRed

	activeUIWidth      = uiWidth
	colorOutputEnabled = true
)

func enableColors() {
	colorOutputEnabled = true
	rst, bld, dm, itl, ul = ansiReset, ansiBold, ansiDim, ansiItalic, ansiUnderline
	cLavender, cMint, cAmber, cRose, cIce = ansiBlue, ansiGreen, ansiYellow, ansiRed, ansiCyan
	cPeach, cSilver, cSlate, cGhost, cCloud = ansiOrange, ansiText, ansiMuted, ansiFrame, ansiBright
	cLilac, cTeal, cSky, cCoral, cFrost = ansiPurple, ansiCyan, ansiBlue, ansiRed, ansiCyan
	bLavender, bMint, bAmber = ansiBold+ansiBlue, ansiBold+ansiGreen, ansiBold+ansiYellow
	bRose, bIce, bPeach = ansiBold+ansiRed, ansiBold+ansiCyan, ansiBold+ansiOrange
	bCloud, bLilac, bTeal, bCoral = ansiBold+ansiBright, ansiBold+ansiPurple, ansiBold+ansiCyan, ansiBold+ansiRed
}

func disableColors() {
	colorOutputEnabled = false
	rst, bld, dm, itl, ul = "", "", "", "", ""
	cLavender, cMint, cAmber, cRose, cIce = "", "", "", "", ""
	cPeach, cSilver, cSlate, cGhost, cCloud = "", "", "", "", ""
	cLilac, cTeal, cSky, cCoral, cFrost = "", "", "", "", ""
	bLavender, bMint, bAmber, bRose, bIce = "", "", "", "", ""
	bPeach, bCloud, bLilac, bTeal, bCoral = "", "", "", "", ""
}

func interactiveOutput() bool {
	return isTTY() && os.Getenv("CI") == "" && !strings.EqualFold(os.Getenv("TERM"), "dumb")
}

func configureTerminalStyle() {
	enableColors()
	activeUIWidth = uiWidth
	if columns := terminalColumns(os.Stderr); columns > 0 {
		activeUIWidth = max(minUIWidth, min(maxUIWidth, columns-4))
	}
	_, noColor := os.LookupEnv("NO_COLOR")
	if noColor || !interactiveOutput() || !enableVirtualTerminal(os.Stderr) {
		disableColors()
	}
}

func currentUIWidth() int {
	return max(minUIWidth, min(maxUIWidth, activeUIWidth))
}

// Box drawing primitives shared by every interactive panel.
const (
	boxTL = "╭" // top-left
	boxTR = "╮" // top-right
	boxBL = "╰" // bottom-left
	boxBR = "╯" // bottom-right
	boxH  = "─" // horizontal
	boxV  = "│" // vertical
	boxML = "├" // middle-left
	boxMR = "┤" // middle-right
)

func boxLine(left, fill, right string, width int) string {
	return cGhost + left + strings.Repeat(fill, width+2) + right + rst
}

func boxTextWithBorder(text string, width int, borderColor string) string {
	text = truncateANSI(text, width)
	visLen := visibleLen(text)
	padding := width - visLen
	return borderColor + boxV + rst + " " + text + strings.Repeat(" ", padding) + " " + borderColor + boxV + rst
}

func boxText(text string, width int) string {
	return boxTextWithBorder(text, width, cGhost)
}

func visibleLen(s string) int {
	width := 0
	for i := 0; i < len(s); {
		if s[i] == '\033' {
			i = ansiSequenceEnd(s, i)
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			width++
			continue
		}
		width += runeDisplayWidth(r)
		i += size
	}
	return width
}

func ansiSequenceEnd(s string, start int) int {
	if start < 0 || start >= len(s) || s[start] != '\033' {
		return start + 1
	}
	if start+1 >= len(s) {
		return len(s)
	}
	switch s[start+1] {
	case '[': // CSI: parameters/intermediates followed by a final byte.
		for i := start + 2; i < len(s); i++ {
			if s[i] >= 0x40 && s[i] <= 0x7e {
				return i + 1
			}
		}
		return len(s)
	case ']', 'P', 'X', '^', '_': // OSC/DCS/SOS/PM/APC: BEL or ST terminates.
		for i := start + 2; i < len(s); i++ {
			if s[i] == '\a' {
				return i + 1
			}
			if s[i] == '\033' && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
		}
		return len(s)
	default:
		return min(len(s), start+2)
	}
}

func runeDisplayWidth(r rune) int {
	if r == 0 || unicode.IsControl(r) || unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf) {
		return 0
	}
	// Broad East Asian and emoji ranges are rendered as two cells by modern
	// terminals. Keeping this local avoids a heavy UI dependency.
	if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) || (r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe10 && r <= 0xfe19) || (r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) || (r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1faff) || (r >= 0x20000 && r <= 0x3fffd)) {
		return 2
	}
	return 1
}

// padToWidth pads a visible string to the given width
func padToWidth(s string, width int) string {
	s = truncateANSI(s, width)
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
	for i := 0; i < len(s); {
		if s[i] == '\033' {
			i = ansiSequenceEnd(s, i)
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		i += size
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r) || unicode.In(r, unicode.Cf):
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
	if visibleLen(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := runeDisplayWidth(r)
		if used+rw > width-1 {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	return b.String() + "…"
}

func truncateANSI(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if visibleLen(s) <= width {
		return s
	}
	if width == 1 {
		return "…" + rst
	}
	var b strings.Builder
	used := 0
	for i := 0; i < len(s); {
		if s[i] == '\033' {
			end := ansiSequenceEnd(s, i)
			b.WriteString(s[i:end])
			i = end
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		rw := runeDisplayWidth(r)
		if used+rw > width-1 {
			break
		}
		b.WriteString(s[i : i+size])
		used += rw
		i += size
	}
	b.WriteRune('…')
	b.WriteString(rst)
	return b.String()
}

func isTTY() bool {
	info, err := os.Stderr.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func panelTitle(title, status string, width int, color string) string {
	title = safeTerminalText(title)
	status = safeTerminalText(status)
	inner := width + 2
	right := ""
	if status != "" {
		right = " " + status + " ─"
	}
	maxTitle := inner - visibleLen(right) - 4
	if maxTitle < 1 {
		maxTitle = 1
	}
	left := "─ " + truncateText(title, maxTitle) + " "
	fill := inner - visibleLen(left) - visibleLen(right)
	if fill < 0 {
		fill = 0
	}
	return color + boxTL + left + strings.Repeat(boxH, fill) + right + boxTR + rst
}

func panelDivider(width int, color string) string {
	return color + boxML + strings.Repeat(boxH, width+2) + boxMR + rst
}

func panelBottom(width int, color string) string {
	return color + boxBL + strings.Repeat(boxH, width+2) + boxBR + rst
}

func panelDetail(label, value string, width int, valueColor string) string {
	return panelDetailWithBorder(label, value, width, valueColor, cGhost)
}

func panelDetailWithBorder(label, value string, width int, valueColor, borderColor string) string {
	label = truncateText(safeTerminalText(label), 10)
	value = safeTerminalText(value)
	return boxTextWithBorder(fmt.Sprintf(" %s%-10s%s  %s%s%s", cSlate, label, rst, valueColor, value, rst), width, borderColor)
}

// BANNER — the original AKCA block wordmark.

var akcaASCII = []string{
	` █████╗ ██╗  ██╗ ██████╗ █████╗ `,
	`██╔══██╗██║ ██╔╝██╔════╝██╔══██╗`,
	`███████║█████╔╝ ██║     ███████║`,
	`██╔══██║██╔═██╗ ██║     ██╔══██║`,
	`██║  ██║██║  ██╗╚██████╗██║  ██║`,
	`╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝`,
}

func printASCIIWordmark(w io.Writer) {
	type rgb struct{ r, g, b int }
	lineColors := []rgb{
		{180, 167, 214},
		{165, 175, 212},
		{145, 185, 208},
		{125, 195, 205},
		{110, 200, 200},
		{100, 205, 195},
	}
	for i, line := range akcaASCII {
		c := lineColors[i]
		fmt.Fprintln(w, gradient(line, c.r, c.g, c.b, c.r+30, c.g+15, c.b-10))
	}
}

func gradient(value string, r1, g1, b1, r2, g2, b2 int) string {
	if !colorOutputEnabled {
		return value
	}
	runes := []rune(value)
	if len(runes) <= 1 {
		return fmt.Sprintf("\033[38;2;%d;%d;%dm%s%s", r1, g1, b1, value, rst)
	}
	var b strings.Builder
	for i, ch := range runes {
		t := float64(i) / float64(len(runes)-1)
		r := int(float64(r1) + t*float64(r2-r1))
		g := int(float64(g1) + t*float64(g2-g1))
		blue := int(float64(b1) + t*float64(b2-b1))
		fmt.Fprintf(&b, "\033[38;2;%d;%d;%dm%c", r, g, blue, ch)
	}
	b.WriteString(rst)
	return b.String()
}

func printBanner() {
	w := currentUIWidth()
	fmt.Fprintln(os.Stderr)
	printASCIIWordmark(os.Stderr)
	fmt.Fprintf(os.Stderr, "\n%s◆%s  %s%s%s  %s%s%s\n", bLavender, rst, bCloud, branding.ProductName, rst, cGhost, branding.VersionLabel, rst)
	fmt.Fprintf(os.Stderr, "%s%s%s\n\n", cGhost, strings.Repeat(boxH, w+4), rst)
}

func printCompactBanner() {
	fmt.Fprintln(os.Stderr)
	printASCIIWordmark(os.Stderr)
	fmt.Fprintf(os.Stderr, "%s %s\n", branding.ProductName, branding.VersionLabel)
}

func printVersion() {
	fmt.Fprintln(os.Stderr)
	printASCIIWordmark(os.Stderr)
	fmt.Printf("%s %s\n", branding.ProductName, branding.VersionLabel)
}

type helpEntry struct {
	flag string
	desc string
}

func wrapText(text string, width int) []string {
	text = safeTerminalText(text)
	if text == "" {
		return []string{""}
	}
	if width < 8 {
		width = 8
	}
	var lines []string
	var line string
	for _, word := range strings.Fields(text) {
		if visibleLen(word) > width {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
			for visibleLen(word) > width {
				part := truncateText(word, width)
				part = strings.TrimSuffix(part, "…")
				if part == "" {
					break
				}
				lines = append(lines, part)
				word = strings.TrimPrefix(word, part)
			}
		}
		candidate := word
		if line != "" {
			candidate = line + " " + word
		}
		if visibleLen(candidate) > width {
			lines = append(lines, line)
			line = word
		} else {
			line = candidate
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func printHelpSection(title string, entries []helpEntry) {
	w := currentUIWidth()
	labelWidth := min(28, max(20, w/3))
	descWidth := max(24, w-labelWidth-4)
	fmt.Fprintf(os.Stderr, "%s%s%s  %s%s%s\n", bLavender, strings.ToUpper(title), rst,
		cGhost, strings.Repeat(boxH, max(2, w-visibleLen(title)-2)), rst)
	for _, entry := range entries {
		wrapped := wrapText(entry.desc, descWidth)
		if visibleLen(entry.flag) > labelWidth {
			fmt.Fprintf(os.Stderr, "  %s%s%s\n", cIce, entry.flag, rst)
			for _, line := range wrapped {
				fmt.Fprintf(os.Stderr, "  %-*s  %s%s%s\n", labelWidth, "", cSilver, line, rst)
			}
			continue
		}
		for i, line := range wrapped {
			label := ""
			if i == 0 {
				label = entry.flag
			}
			fmt.Fprintf(os.Stderr, "  %s%-*s%s  %s%s%s\n", cIce, labelWidth, label, rst, cSilver, line, rst)
		}
	}
	fmt.Fprintln(os.Stderr)
}

// HELP — concise by default, exhaustive with --help.

func printShortUsage() {
	printCompactBanner()
	fmt.Fprintf(os.Stderr, "\n%sUSAGE%s\n", bLavender, rst)
	fmt.Fprintf(os.Stderr, "  %sakca -u <url> [options]%s\n", bCloud, rst)
	fmt.Fprintf(os.Stderr, "  %sakca -d <domain> [options]%s\n", bCloud, rst)
	fmt.Fprintf(os.Stderr, "  %sakca <url> [options]%s\n\n", bCloud, rst)

	printHelpSection("Core options", []helpEntry{
		{"-u, --url <url>", "Target base URL (e.g. https://target.com)"},
		{"-d, --domain <domain>", "Scan root domain and discover live subdomains"},
		{"-m, --mode <mode>", "Scan mode: sql, xss, api, graphql, rce, ssrf, auth, passive, full"},
		{"-o, --output <file>", "Report output file path"},
		{"-f, --format <type>", "html, json, markdown, csv or sarif (default: html)"},
		{"-c, --cookie <str>", "Authentication cookie string"},
		{"-H, --header <hdr>", "Custom HTTP header (repeatable)"},
		{"-p, --proxy <url>", "Upstream HTTP/S proxy (e.g. http://127.0.0.1:8080)"},
		{"-k, --insecure", "Skip TLS/SSL certificate verification"},
		{"-v, --verbose", "Show detailed diagnostic logs and skipped checks"},
		{"-q, --quiet", "Machine-friendly lifecycle and finding lines"},
		{"-h, --help", "Show the complete command reference"},
	})

	fmt.Fprintf(os.Stderr, "%sExamples%s\n", bLavender, rst)
	fmt.Fprintf(os.Stderr, "  %sakca -u https://example.com -m sql,xss%s\n", cSilver, rst)
	fmt.Fprintf(os.Stderr, "  %sakca -d example.com -m passive -v%s\n", cSilver, rst)
	fmt.Fprintf(os.Stderr, "  %sakca replay --finding 42%s\n\n", cSilver, rst)
	fmt.Fprintf(os.Stderr, "%sUse 'akca --help' for every scan budget and advanced option.%s\n\n", cSlate, rst)
}

func printDetailedUsage() {
	if interactiveOutput() {
		printBanner()
	} else {
		printCompactBanner()
	}

	fmt.Fprintf(os.Stderr, "%sUSAGE%s\n", bLavender, rst)
	fmt.Fprintf(os.Stderr, "  %sakca -u <url> [options]%s\n", bCloud, rst)
	fmt.Fprintf(os.Stderr, "  %sakca -d <domain> [options]%s\n", bCloud, rst)
	fmt.Fprintf(os.Stderr, "  %sakca <url> [options]%s\n\n", bCloud, rst)

	printHelpSection("Target and authentication", []helpEntry{
		{"-u, --url <url>", "Scan one target URL"},
		{"-d, --domain <domain>", "Discover live subdomains and scan the root scope"},
		{"-r, --resume <id>", "Resume an interrupted scan from its checkpoint"},
		{"-c, --cookie <value>", "Session Cookie header"},
		{"-H, --header <value>", "Custom Name: Value request header; repeatable"},
		{"-p, --proxy <url>", "Route HTTP/S traffic through an upstream proxy"},
		{"-k, --insecure", "Skip target TLS certificate verification"},
		{"--api-spec <path>", "Import OpenAPI 3.1, RAML/ZIP, Postman, HAR, WSDL, GraphQL or protobuf; repeatable"},
	})

	printHelpSection("Scan modes", []helpEntry{
		{"full", "Comprehensive active and passive assessment (default)"},
		{"sql, sqli", "SQL and NoSQL injection"},
		{"xss", "Reflected, DOM, stored and blind XSS"},
		{"api", "REST/JSON, schema, BOLA/IDOR and mass assignment"},
		{"graphql, gql", "GraphQL schema and operation security"},
		{"rce, injection", "Command injection, SSTI and deserialization"},
		{"ssrf, oast", "SSRF, XXE and out-of-band verification"},
		{"auth, privesc", "Authentication, authorization, CSRF and session checks"},
		{"passive, recon", "Non-mutating reconnaissance and exposure analysis"},
		{"fuzz, discovery", "Path, archive and source-disclosure discovery"},
		{"-m <a,b,c>", "Combine modes with commas"},
	})

	printHelpSection("Traffic and budgets", []helpEntry{
		{"--rate-limit <n>", "Maximum requests per second"},
		{"--per-host-rate <n>", "Maximum requests per second for one host"},
		{"--concurrency <n>", "Maximum concurrent workers"},
		{"--per-host-concurrency <n>", "Maximum concurrent workers for one host"},
		{"--max-pages <n>", "Maximum crawled URLs; 0 means unlimited"},
		{"--max-endpoints <n>", "Maximum retained endpoints; 0 means unlimited"},
		{"--max-depth <n>", "Optional crawl depth cap; 0 means unlimited"},
		{"--crawler-budget <n>", "Discovery request budget; 0 means unlimited"},
		{"--request-budget <n>", "Maximum total requests; 0 means unlimited"},
		{"--time-budget <duration>", "Maximum duration such as 30m or 2h; 0 means unlimited"},
		{"--memory-limit <mb>", "Process memory limit; 0 means automatic"},
		{"--include-linked-api-subdomains", "Also crawl linked API/service subdomains under the same root"},
		{"--scan-id <id>", "Deterministic scan identifier for automation"},
	})

	printHelpSection("Engine", []helpEntry{
		{"--waf-evasion", "Force WAF-adaptive request mutations"},
		{"--no-waf-evasion", "Disable WAF-adaptive request mutations"},
		{"--no-oast", "Disable DNS/HTTP out-of-band probes"},
		{"--oast-server <urls>", "Custom OAST server APIs in priority order"},
		{"--oast-wait <seconds>", "Final callback collection window (default: 60)"},
		{"--no-fuzzing", "Disable path and directory fuzzing"},
		{"--no-js", "Disable JavaScript and AST analysis"},
	})

	printHelpSection("Output", []helpEntry{
		{"-o, --output <path>", "Report destination; use - to write the report to stdout"},
		{"-f, --format <type>", "html, json, markdown, csv or sarif (default: html)"},
		{"-v, --verbose", "Detailed diagnostics and skipped checks"},
		{"-q, --quiet", "Stable machine-friendly lifecycle and finding output"},
		{"NO_COLOR=1", "Disable ANSI styling"},
		{"--version", "Print the version"},
		{"-h, --help", "Print this reference"},
	})

	printHelpSection("Commands", []helpEntry{
		{"replay --finding <id>", "Replay and re-verify stored evidence"},
		{"benchmark [--strict]", "Run the observed quality gate benchmark"},
		{"help", "Print this command reference"},
		{"version", "Print the version"},
	})

	printHelpSection("Examples", []helpEntry{
		{"akca -u https://target.test", "Full assessment"},
		{"akca -u https://target.test -m sql,xss", "Combined injection modes"},
		{"akca -d example.com -m passive -v", "Verbose passive domain reconnaissance"},
		{"akca -u target.test -p http://127.0.0.1:8080 -k", "Proxy-routed test"},
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
	var clean []string
	switch targets := payload["targets"].(type) {
	case []string:
		for _, target := range targets {
			if value := safeTerminalText(target); value != "" {
				clean = append(clean, value)
			}
		}
	case []interface{}:
		for _, target := range targets {
			if value := safeTerminalText(fmt.Sprint(target)); value != "" {
				clean = append(clean, value)
			}
		}
	case string:
		if value := safeTerminalText(targets); value != "" {
			return value
		}
	}
	if len(clean) == 1 {
		return clean[0]
	} else if len(clean) > 1 {
		first := clean[0]
		u, err := url.Parse(first)
		if err == nil && u.Hostname() != "" {
			parts := strings.Split(u.Hostname(), ".")
			if len(parts) >= 2 {
				root := parts[len(parts)-2] + "." + parts[len(parts)-1]
				return fmt.Sprintf("*.%s (%d Live Subdomains)", root, len(clean))
			}
		}
		return fmt.Sprintf("%s (+%d Subdomains)", first, len(clean)-1)
	}
	return "unknown target"
}

func scanSessionPanel(payload map[string]interface{}) string {
	w := currentUIWidth()
	targets := truncateText(payloadTargets(payload), w-10)
	rate := payloadFloat(payload, "global_rate_limit")
	maxPages := payloadInt(payload, "max_pages")
	subdomainCount := payloadInt(payload, "subdomain_count")
	maxDepth := payloadInt(payload, "max_depth")
	memoryLimit := payloadInt(payload, "memory_limit_mb")
	memorySource := safeTerminalText(fmt.Sprint(payload["memory_limit_source"]))
	maxEndpoints := payloadInt(payload, "max_endpoints")
	crawlerBudget := payloadInt(payload, "crawler_request_budget")
	requestBudget := payloadInt(payload, "request_budget")
	payloadBudget := safeTerminalText(fmt.Sprint(payload["payload_budget"]))
	if payloadBudget == "" || payloadBudget == "<nil>" {
		payloadBudget = "unlimited"
	}
	oastStatus, oastColor := sessionOASTStatus(payload)
	profile := safeTerminalText(fmt.Sprint(payload["scan_profile"]))
	if profile == "" || profile == "<nil>" {
		profile = safeTerminalText(fmt.Sprint(payload["scan_intensity"]))
	}
	if profile == "" || profile == "<nil>" {
		profile = "default"
	}
	profile = truncateText(profile, 20)

	// Format discovery breadth as URLs; payload traffic has its own unlimited
	// default and therefore does not consume this count.
	pagesStr := ""
	switch {
	case maxPages >= 10000:
		pagesStr = fmt.Sprintf("%.0fK URLs", float64(maxPages)/1000)
	case maxPages > 0:
		pagesStr = fmt.Sprintf("%d URLs", maxPages)
	default:
		pagesStr = "unlimited URLs"
	}

	scopeStr := ""
	if subdomainCount > 1 {
		scopeStr = fmt.Sprintf("  %s•%s  %s%d subdomains%s", cGhost, rst, cAmber, subdomainCount, rst)
	} else if maxDepth > 0 {
		scopeStr = fmt.Sprintf("  %s•%s  %sdepth %d%s", cGhost, rst, cSlate, maxDepth, rst)
	}
	totalBudget := "unlimited"
	if requestBudget > 0 {
		totalBudget = fmt.Sprintf("%d", requestBudget)
	}
	memory := "automatic"
	if memoryLimit > 0 {
		mode := "manual"
		if strings.HasPrefix(memorySource, "automatic_") {
			mode = "auto"
		}
		memory = fmt.Sprintf("%d MB (%s)", memoryLimit, mode)
	}

	var b strings.Builder
	b.WriteString(panelTitle("SCAN SESSION", "RUNNING", w, cLavender) + "\n")
	b.WriteString(boxText(fmt.Sprintf(" %sTarget%s    %s%s%s", cSlate, rst, cIce, targets, rst), w) + "\n")
	b.WriteString(panelDivider(w, cGhost) + "\n")
	b.WriteString(boxText(fmt.Sprintf(" %sMode%s      %s%s%s  %s•%s  %s%.0f req/s%s  %s•%s  OAST %s%s%s",
		cSlate, rst, cFrost, profile, rst, cGhost, rst, cSilver, rate, rst,
		cGhost, rst, oastColor, oastStatus, rst), w) + "\n")
	b.WriteString(boxText(fmt.Sprintf(" %sCrawl%s     %s%s%s  %s•%s  %s%d endpoints%s%s",
		cSlate, rst, cSilver, pagesStr, rst, cGhost, rst, cSilver, maxEndpoints, rst, scopeStr), w) + "\n")
	b.WriteString(boxText(fmt.Sprintf(" %sBudget%s    %s%d crawler requests%s  %s•%s  %stotal %s%s",
		cSlate, rst, cSilver, crawlerBudget, rst, cGhost, rst, cSilver, totalBudget, rst), w) + "\n")
	b.WriteString(boxText(fmt.Sprintf(" %sPayloads%s  %s%s%s  %s•%s  %sMemory %s%s",
		cSlate, rst, cSilver, payloadBudget, rst, cGhost, rst, cSilver, memory, rst), w) + "\n")
	b.WriteString(panelBottom(w, cLavender) + "\n\n")
	return b.String()
}

func scanSessionLine(payload map[string]interface{}) string {
	total := "unlimited"
	if budget := payloadInt(payload, "request_budget"); budget > 0 {
		total = fmt.Sprint(budget)
	}
	payloadBudget := safeTerminalText(fmt.Sprint(payload["payload_budget"]))
	if payloadBudget == "" || payloadBudget == "<nil>" {
		payloadBudget = "unlimited"
	}
	memory := "auto"
	if limit := payloadInt(payload, "memory_limit_mb"); limit > 0 {
		memory = fmt.Sprintf("%dMB", limit)
	}
	return fmt.Sprintf("SCAN START target=%s profile=%s urls=%d endpoints=%d crawler_requests=%d payloads=%s total_requests=%s memory=%s",
		payloadTargets(payload), safeTerminalText(fmt.Sprint(payload["scan_profile"])),
		payloadInt(payload, "max_pages"), payloadInt(payload, "max_endpoints"),
		payloadInt(payload, "crawler_request_budget"), payloadBudget, total, memory)
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
		"crawling":            "Crawling Application Surface",
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

	return cMint + strings.Repeat("━", filled) + cGhost + strings.Repeat("─", empty) + rst
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SLICE FLAG — Repeatable -H headers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

type sliceFlag []string

func flagWasSet(fs *flag.FlagSet, name string) bool {
	wasSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			wasSet = true
		}
	})
	return wasSet
}

func normalizeScanArgs(args []string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args
	}
	normalized := make([]string, 0, len(args)+1)
	normalized = append(normalized, "--url", args[0])
	normalized = append(normalized, args[1:]...)
	return normalized
}

func (s *sliceFlag) String() string { return strings.Join(*s, ", ") }
func (s *sliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  CONSOLE WRITER — Event-Driven Display Engine
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

type ConsoleWriter struct {
	mu                 sync.Mutex
	renderMu           sync.Mutex
	out                io.Writer
	detected           int
	verified           int
	severityMap        map[string]int
	startTime          time.Time
	lastPhase          string
	lastFinished       string
	lastProgress       string
	maxDiscovered      int
	maxTested          int
	lastSnapshot       time.Time
	lastTraffic        string
	mode               string
	interactive        bool
	target             string
	scanProfile        string
	scanStatus         string
	oastEnabled        bool
	requestRate        float64
	peakRequestRate    float64
	scanActive         bool
	urlLimit           int
	memoryLimitMB      int
	urlsCrawled        int
	crawlerComplete    bool
	parameterCompleted int
	parameterTotal     int
	moduleCompleted    int
	moduleTotal        int
	progressPercent    int
	payloadProbes      int
	processMemoryMB    int
	etaEstimate        time.Duration
	eta                string
	requests           int
	oastProbes         int
	oastCallbacks      int
	coverageGaps       int
	suppressed         int
	skipped            int
	progressLineOpen   bool
	reportDone         bool
	phaseIndex         int
	phaseStarted       map[string]time.Time
	oastSeen           map[string]struct{}
}

func NewConsoleWriter() *ConsoleWriter {
	return NewConsoleWriterMode("normal")
}

func NewConsoleWriterMode(mode string) *ConsoleWriter {
	now := time.Now()
	return &ConsoleWriter{
		out:          os.Stderr,
		severityMap:  make(map[string]int),
		phaseStarted: make(map[string]time.Time),
		oastSeen:     make(map[string]struct{}),
		startTime:    now,
		lastSnapshot: now.Add(-10 * time.Second),
		mode:         mode,
		interactive:  interactiveOutput(),
	}
}

func (cw *ConsoleWriter) acceptOASTCallback(payload map[string]interface{}) bool {
	protocol := strings.ToLower(safeTerminalText(fmt.Sprint(payload["protocol"])))
	module := strings.ToLower(safeTerminalText(fmt.Sprint(payload["vuln_class"])))
	endpoint := strings.ToLower(safeTerminalText(fmt.Sprint(payload["endpoint"])))
	parameter := strings.ToLower(safeTerminalText(fmt.Sprint(payload["parameter"])))
	key := strings.Join([]string{protocol, module, endpoint, parameter}, "|")

	cw.mu.Lock()
	defer cw.mu.Unlock()
	if cw.oastSeen == nil {
		cw.oastSeen = make(map[string]struct{})
	}
	if _, exists := cw.oastSeen[key]; exists {
		return false
	}
	cw.oastSeen[key] = struct{}{}
	cw.oastCallbacks++
	return true
}

func oastCallbackPanel(payload map[string]interface{}) string {
	protocol := strings.ToUpper(safeTerminalText(fmt.Sprint(payload["protocol"])))
	if protocol == "" || protocol == "<NIL>" {
		protocol = "OAST"
	}
	module := strings.ToLower(safeTerminalText(fmt.Sprint(payload["vuln_class"])))
	if module == "<nil>" {
		module = ""
	}
	endpoint := safeTerminalText(fmt.Sprint(payload["endpoint"]))
	if endpoint == "<nil>" {
		endpoint = ""
	}
	parameter := safeTerminalText(fmt.Sprint(payload["parameter"]))
	if parameter == "<nil>" {
		parameter = ""
	}

	status, statusColor := "CONFIRMED", bMint
	proof, frameColor := "Correlated OAST interaction received", bMint
	if protocol == "DNS" {
		status, statusColor = "HIGH CONFIDENCE", bAmber
		proof, frameColor = "Server-side DNS resolution observed", bAmber
	}
	title := "Blind Callback"
	if module != "" {
		title = findingtext.HumanTitle(module)
	}

	w := currentUIWidth()
	var out strings.Builder
	out.WriteByte('\n')
	out.WriteString(panelTitle("OAST CALLBACK", status, w, frameColor) + "\n")
	out.WriteString(boxTextWithBorder(fmt.Sprintf(" %s%s CALLBACK%s  %s•%s  %s%s%s",
		statusColor, protocol, rst, cGhost, rst, bCloud, title, rst), w, frameColor) + "\n")
	out.WriteString(panelDivider(w, frameColor) + "\n")

	type detail struct{ label, value, color string }
	details := []detail{{"Status", status, statusColor}}
	if module != "" {
		details = append(details, detail{"Class", strings.ToUpper(module), cSilver})
	}
	if endpoint != "" {
		details = append(details, detail{"URL", endpoint, cIce})
	}
	if parameter != "" {
		details = append(details, detail{"Param", parameter, cFrost})
	}
	details = append(details, detail{"Proof", proof, statusColor})
	for _, item := range details {
		out.WriteString(panelDetailWithBorder(item.label, item.value, w, item.color, frameColor) + "\n")
	}
	out.WriteString(panelBottom(w, frameColor) + "\n")
	return out.String()
}

func quietEvent(eventType string) bool {
	switch eventType {
	case "scan_finished", "scan_stopping", "scan_stopped", "scan_error", "resource_limit_reached",
		"finding_detected", "finding_verified", "oast_callback_received":
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
	cw.renderMu.Lock()
	defer cw.renderMu.Unlock()
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

func clockDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalSeconds := int64(d / time.Second)
	hours := totalSeconds / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

func scanProgressPercent(phase string, crawled, urlLimit int, crawlerComplete bool, parameterCompleted, parameterTotal, moduleCompleted, moduleTotal int) int {
	clampRatio := func(value, total, span int) int {
		if total <= 0 || value <= 0 {
			return 0
		}
		return min(span, (min(value, total)*span)/total)
	}
	switch {
	case phase == "bootstrap":
		return 1
	case phase == "fingerprinting" || phase == "fingerprint":
		return 3
	case phase == "learning_waf":
		return 6
	case phase == "crawling":
		if crawlerComplete {
			return 30
		}
		return 8 + clampRatio(crawled, urlLimit, 22)
	case phase == "sensor_discovery":
		return 31
	case phase == "js_analysis" || phase == "js_api_crawl" || phase == "shadow_api":
		return 33
	case phase == "parameter_discovery":
		return 35 + clampRatio(parameterCompleted, parameterTotal, 7)
	case phase == "fuzzing":
		return 43
	case phase == "auth_bypass" || phase == "bypass403":
		return 45
	case phase == "reflection":
		return 47
	case strings.HasPrefix(phase, "vuln_module_"):
		return 48 + clampRatio(moduleCompleted, moduleTotal, 47)
	case phase == "oast_drain":
		return 97
	case phase == "report_generation":
		return 99
	default:
		return 0
	}
}

func (cw *ConsoleWriter) updateProgressLocked() {
	candidate := scanProgressPercent(cw.lastPhase, cw.urlsCrawled, cw.urlLimit, cw.crawlerComplete,
		cw.parameterCompleted, cw.parameterTotal, cw.moduleCompleted, cw.moduleTotal)
	if candidate > cw.progressPercent {
		cw.progressPercent = candidate
	}
}

func (cw *ConsoleWriter) updateETALocked(now time.Time) {
	percent := cw.progressPercent
	elapsed := now.Sub(cw.startTime)
	if percent < 2 || percent >= 100 || elapsed < 15*time.Second {
		cw.eta = "Calculating"
		return
	}
	estimate := time.Duration(float64(elapsed) * float64(100-percent) / float64(percent))
	if cw.etaEstimate > 0 {
		estimate = time.Duration(0.75*float64(cw.etaEstimate) + 0.25*float64(estimate))
	}
	cw.etaEstimate = estimate
	cw.eta = clockDuration(estimate)
}

func compactCount(value int) string {
	switch {
	case value >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(value)/1_000_000)
	case value >= 10_000:
		return fmt.Sprintf("%.1fK", float64(value)/1_000)
	default:
		return fmt.Sprint(value)
	}
}

func runningPanelTop(status string) string {
	return panelTitle("LIVE SCAN", status, currentUIWidth(), cLavender)
}

func statusPair(leftLabel, leftValue string, leftWidth int, rightLabel, rightValue string) string {
	w := currentUIWidth()
	leftWidth = min(leftWidth, max(12, w/2-10))
	leftValue = truncateText(safeTerminalText(leftValue), leftWidth)
	rightWidth := w - 1 - 9 - 2 - leftWidth - 1 - 8 - 2
	if rightWidth < 1 {
		rightWidth = 1
	}
	rightValue = truncateText(safeTerminalText(rightValue), rightWidth)
	return fmt.Sprintf(" %s%-9s%s: %s%-*s%s %s%-8s%s: %s%s%s",
		cSlate, leftLabel, rst, cCloud, leftWidth, leftValue, rst,
		cSlate, rightLabel, rst, cCloud, rightValue, rst)
}

func (cw *ConsoleWriter) runningStatusPanel() string {
	w := currentUIWidth()
	cw.mu.Lock()
	target := cw.target
	profile := cw.scanProfile
	status := cw.scanStatus
	oastEnabled := cw.oastEnabled
	rate := cw.requestRate
	peakRate := cw.peakRequestRate
	urlsCrawled := cw.urlsCrawled
	urlLimit := cw.urlLimit
	percent := cw.progressPercent
	processMemoryMB := cw.processMemoryMB
	memoryLimitMB := cw.memoryLimitMB
	eta := cw.eta
	cw.mu.Unlock()

	if target == "" {
		target = "waiting for target"
	}
	if profile == "" || profile == "<nil>" {
		profile = "Full Scan"
	}
	if status == "" {
		status = "RUNNING"
	}
	oast := "Disabled"
	if oastEnabled {
		oast = "Ready (Active)"
	}
	if eta == "" {
		eta = "Calculating"
	}
	crawled := fmt.Sprintf("%s / %s URLs", compactCount(urlsCrawled), compactCount(urlLimit))
	memory := fmt.Sprintf("%d MB", processMemoryMB)
	if memoryLimitMB > 0 {
		memory = fmt.Sprintf("%d / %d MB", processMemoryMB, memoryLimitMB)
	}

	var b strings.Builder
	b.WriteString(runningPanelTop(status) + "\n")
	b.WriteString(boxText(statusPair("Target", target, 30, "Mode", profile), w) + "\n")
	b.WriteString(boxText(statusPair("Speed", fmt.Sprintf("%.1f req/s (peak: %.1f)", rate, peakRate), 30, "OAST", oast), w) + "\n")
	progress := fmt.Sprintf(" %s%-9s%s: [%s] %s%3d%%%s  %s%-8s%s: %s%s%s",
		cSlate, "Progress", rst, progressBar(percent, 18), bCloud, percent, rst,
		cSlate, "ETA", rst, cCloud, eta, rst)
	b.WriteString(boxText(progress, w) + "\n")
	b.WriteString(boxText(statusPair("Crawled", crawled, 30, "Memory", memory), w) + "\n")
	b.WriteString(panelBottom(w, cLavender))
	return b.String()
}

func (cw *ConsoleWriter) runningStatusLine() string {
	cw.mu.Lock()
	percent := cw.progressPercent
	phase := phaseLabel(cw.lastPhase)
	rate := cw.requestRate
	urls := cw.urlsCrawled
	urlLimit := cw.urlLimit
	eta := cw.eta
	cw.mu.Unlock()
	if phase == "" {
		phase = "Preparing scan"
	}
	if eta == "" {
		eta = "Calculating"
	}
	w := currentUIWidth() + 4
	barWidth := 12
	if w < 68 {
		barWidth = 8
	}
	line := fmt.Sprintf("%sRUN%s  [%s] %s%3d%%%s  %s%s%s  %s•%s  %.1f req/s",
		bLavender, rst, progressBar(percent, barWidth), bCloud, percent, rst,
		cSilver, truncateText(phase, max(12, w/3)), rst, cGhost, rst, rate)
	if w >= 68 {
		line += fmt.Sprintf("  %s•%s  %s/%s URLs", cGhost, rst, compactCount(urls), compactCount(urlLimit))
	}
	if w >= 84 {
		line += fmt.Sprintf("  %s•%s  ETA %s", cGhost, rst, eta)
	}
	return truncateANSI(line, w)
}

func (cw *ConsoleWriter) closeProgressLine() {
	cw.mu.Lock()
	open := cw.progressLineOpen
	cw.progressLineOpen = false
	cw.mu.Unlock()
	if !open {
		return
	}
	fmt.Fprint(cw.outputWriter(), "\r\033[2K")
}

func (cw *ConsoleWriter) writeProgressLine(line string) {
	if !cw.interactive {
		return
	}
	cw.mu.Lock()
	cw.progressLineOpen = true
	cw.mu.Unlock()
	// Overwrite the entire live row without clearing it first. Padding removes
	// remnants of a longer previous value while avoiding the visible blank
	// frame that made the bar flicker during crawler health snapshots.
	width := currentUIWidth() + 4
	fmt.Fprintf(cw.outputWriter(), "\r%s", padToWidth(line, width))
}

func (cw *ConsoleWriter) writeRunningStatus() {
	cw.mu.Lock()
	active := cw.scanActive
	cw.mu.Unlock()
	if !cw.interactive || !active {
		return
	}
	cw.writeProgressLine(cw.runningStatusLine())
}

func (cw *ConsoleWriter) outputWriter() io.Writer {
	if cw.out != nil {
		return cw.out
	}
	return os.Stderr
}

func (cw *ConsoleWriter) eventNeedsProgressClose(e events.Event) bool {
	if !cw.interactive {
		return false
	}
	switch e.Type {
	case "health_snapshot", "parameter_discovery_progress", "report_generation_progress", "finding_verified":
		return false
	case "plugin_skipped":
		return cw.mode == "verbose"
	case "crawler_started", "crawler_finished", "oast_started", "oast_probe_sent":
		return cw.mode == "verbose"
	case "scan_progress":
		msg := safeTerminalText(e.Message)
		return msg != "" && msg != "crawling" && msg != "fuzzing" && msg != "fingerprinting" && msg != "bypass403" && msg != "reflection"
	default:
		return true
	}
}

func (cw *ConsoleWriter) handleEvent(e events.Event) error {
	if cw.mode == "quiet" && !quietEvent(e.Type) {
		return nil
	}
	closeProgress := cw.eventNeedsProgressClose(e)
	if closeProgress {
		cw.closeProgressLine()
		defer cw.writeRunningStatus()
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
		fmt.Fprintf(cw.outputWriter(), "%s%s%s %s%s%s\n",
			cGhost, "╎", rst, cSlate, msg, rst)

	// ── Scan lifecycle ──────────────────────────────────────────────────
	case "scan_started":
		cw.mu.Lock()
		cw.scanActive = true
		cw.scanStatus = "RUNNING"
		cw.target = payloadTargets(e.Payload)
		cw.scanProfile = safeTerminalText(fmt.Sprint(e.Payload["scan_profile"]))
		if cw.scanProfile == "" || cw.scanProfile == "<nil>" || strings.EqualFold(cw.scanProfile, "FullBugBounty") {
			cw.scanProfile = "Full Scan"
		}
		cw.oastEnabled = payloadBool(e.Payload, "oast_enabled")
		cw.requestRate = payloadFloat(e.Payload, "global_rate_limit")
		cw.peakRequestRate = cw.requestRate
		cw.urlLimit = payloadInt(e.Payload, "max_pages")
		cw.memoryLimitMB = payloadInt(e.Payload, "memory_limit_mb")
		cw.mu.Unlock()
		if cw.interactive {
			fmt.Fprint(cw.outputWriter(), scanSessionPanel(e.Payload))
		} else {
			fmt.Fprintln(cw.outputWriter(), scanSessionLine(e.Payload))
		}

	case "scan_resumed":
		cw.mu.Lock()
		cw.scanActive = true
		cw.mu.Unlock()
		phase := ""
		if p, ok := e.Payload["phase"].(string); ok {
			phase = p
		}
		fmt.Fprintf(cw.outputWriter(), "\n%s◈%s  %sResuming scan from checkpoint%s  %sphase: %s%s\n\n",
			cSky, rst, bCloud, rst, cMint, phaseLabel(phase), rst)

	case "scan_finished":
		cw.mu.Lock()
		cw.progressPercent = 100
		cw.scanStatus = "COMPLETE"
		cw.mu.Unlock()
		cw.mu.Lock()
		cw.scanActive = false
		cw.mu.Unlock()
		if !cw.interactive {
			fmt.Fprintf(cw.outputWriter(), "SCAN COMPLETE duration=%s\n", cw.elapsed())
			return nil
		}
		fmt.Fprintf(cw.outputWriter(), "\n%s◉%s  %sScan complete%s  %s◷ %s%s\n",
			cMint, rst, bMint, rst, cSlate, cw.elapsed(), rst)

	case "scan_stopping":
		cw.mu.Lock()
		cw.scanStatus = "STOPPING"
		cw.mu.Unlock()
		if !cw.interactive {
			fmt.Fprintln(cw.outputWriter(), "SCAN STOPPING reason=user_interrupt")
		}

	case "scan_stopped":
		cw.mu.Lock()
		cw.scanStatus = "STOPPED"
		cw.mu.Unlock()
		cw.mu.Lock()
		cw.scanActive = false
		cw.mu.Unlock()
		if !cw.interactive {
			fmt.Fprintln(cw.outputWriter(), "SCAN STOPPED reason=user_interrupt")
			return nil
		}
		fmt.Fprintf(cw.outputWriter(), "\n")
		fmt.Fprintf(cw.outputWriter(), "%s◈%s  %sScan Aborted by User%s\n",
			cAmber, rst, bAmber, rst)

	case "scan_error":
		if !cw.interactive {
			fmt.Fprintf(cw.outputWriter(), "SCAN ERROR message=%s\n", safeTerminalText(e.Message))
			return nil
		}
		fmt.Fprintf(cw.outputWriter(), "%s✖%s  %s%s%s\n",
			cRose, rst, cRose, safeTerminalText(e.Message), rst)

	case "resource_limit_reached":
		resource := safeTerminalText(fmt.Sprint(e.Payload["resource"]))
		if !cw.interactive {
			fmt.Fprintf(cw.outputWriter(), "RESOURCE LIMIT resource=%s message=%s recoverable=%t\n",
				resource, safeTerminalText(e.Message), payloadBool(e.Payload, "recoverable"))
			return nil
		}
		fmt.Fprintf(cw.outputWriter(), "%s[RESOURCE LIMIT]%s  %s%s%s\n",
			bAmber, rst, cAmber, safeTerminalText(e.Message), rst)

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
		if moduleIndex := payloadInt(e.Payload, "module_index"); moduleIndex > 0 {
			cw.moduleCompleted = moduleIndex - 1
			cw.moduleTotal = payloadInt(e.Payload, "module_total")
		}
		cw.updateProgressLocked()
		cw.phaseIndex++
		phaseIndex := cw.phaseIndex
		cw.phaseStarted[phase] = time.Now()
		cw.mu.Unlock()

		label := phaseLabel(phase)
		icon := phaseIcon(phase)
		if !cw.interactive {
			fmt.Fprintf(cw.outputWriter(), "PHASE START name=%s\n", safeTerminalText(label))
			return nil
		}

		fmt.Fprintf(cw.outputWriter(), "%s%02d%s  %s%s%s  %s%s%s  %sRUNNING%s\n",
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
		if phase == "crawling" {
			cw.crawlerComplete = true
		}
		if moduleIndex := payloadInt(e.Payload, "module_index"); moduleIndex > 0 {
			cw.moduleCompleted = moduleIndex
			cw.moduleTotal = payloadInt(e.Payload, "module_total")
		}
		cw.updateProgressLocked()
		started := cw.phaseStarted[phase]
		cw.mu.Unlock()

		duration := ""
		elapsed := time.Duration(0)
		if !started.IsZero() {
			elapsed = time.Since(started)
			duration = fmt.Sprintf("  %s%s%s", cGhost, shortDuration(elapsed), rst)
		}
		if !cw.interactive {
			fmt.Fprintf(cw.outputWriter(), "PHASE COMPLETE name=%s duration=%s\n", safeTerminalText(phaseLabel(phase)), shortDuration(elapsed))
			return nil
		}
		fmt.Fprintf(cw.outputWriter(), "    %s╰─%s %s✓ COMPLETE%s%s\n",
			cGhost, rst, cMint, rst, duration)

	// ── Progress messages ───────────────────────────────────────────────
	case "scan_progress":
		msg := safeTerminalText(e.Message)
		if msg == "crawling" {
			cw.mu.Lock()
			if pages := payloadInt(e.Payload, "pages"); pages > cw.urlsCrawled {
				cw.urlsCrawled = pages
			}
			cw.updateProgressLocked()
			cw.mu.Unlock()
			return nil
		}
		if !cw.interactive {
			if cw.mode == "verbose" && msg != "" {
				fmt.Fprintf(cw.outputWriter(), "PROGRESS message=%s\n", msg)
			}
			return nil
		}
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
		fmt.Fprintf(cw.outputWriter(), "%s⟳%s  %s%s%s\n",
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
		_, statusLabel, statusCol, confirmed := findingStatus(confidence)

		cw.mu.Lock()
		cw.detected++
		sev := strings.ToLower(severity)
		cw.severityMap[sev]++
		if confirmed {
			cw.verified++
		}
		cw.mu.Unlock()

		sevCol := severityColor(sev)
		if !cw.interactive {
			fmt.Fprintf(cw.outputWriter(), "FINDING severity=%s confidence=%s score=%.2f class=%s method=%s url=%s parameter=%s title=%s\n",
				strings.ToUpper(sev), confidence, score, vulnClass, strings.ToUpper(method), endpoint, parameter, title)
			return nil
		}

		w := currentUIWidth()
		fmt.Fprintln(cw.outputWriter())
		fmt.Fprintln(cw.outputWriter(), panelTitle("SECURITY FINDING", fmt.Sprintf("%s · %.2f", statusLabel, score), w, sevCol))
		badge := severityBadge(sev)
		fmt.Fprintln(cw.outputWriter(), boxTextWithBorder(fmt.Sprintf(" %s  %s%s%s", badge, bCloud, title, rst), w, sevCol))
		fmt.Fprintln(cw.outputWriter(), panelDivider(w, sevCol))

		type detailLine struct {
			label string
			value string
			color string
		}
		var details []detailLine
		if vulnClass != "" {
			details = append(details, detailLine{"Class", formatVulnType(vulnClass, signalVal), cSilver})
		}
		if endpoint != "" {
			request := endpoint
			if method != "" {
				request = strings.ToUpper(method) + "  " + endpoint
			}
			details = append(details, detailLine{"Request", request, cIce})
		}
		if parameter != "" {
			paramValue := parameter
			if location != "" {
				paramValue += "  ·  " + strings.ToUpper(location)
			}
			details = append(details, detailLine{"Parameter", paramValue, cFrost})
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
			details = append(details, detailLine{"Evidence", proof, statusCol})
		}
		if payloadStr != "" {
			details = append(details, detailLine{"Payload", payloadStr, cFrost})
		}

		for _, detail := range details {
			fmt.Fprintln(cw.outputWriter(), panelDetailWithBorder(detail.label, detail.value, w, detail.color, sevCol))
		}
		fmt.Fprintln(cw.outputWriter(), panelBottom(w, sevCol))

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
		if !cw.interactive || cw.mode != "verbose" {
			return nil
		}
		fmt.Fprintf(cw.outputWriter(), "%sTRACE%s  %sCrawler workers started%s\n",
			cGhost, rst, cSlate, rst)

	case "crawler_finished":
		pages := 0
		if p, ok := e.Payload["pages"].(float64); ok {
			pages = int(p)
		} else if p, ok := e.Payload["pages_crawled"].(float64); ok {
			pages = int(p)
		}
		cw.mu.Lock()
		cw.requests = max(cw.requests, payloadInt(e.Payload, "requests"))
		if pages > cw.urlsCrawled {
			cw.urlsCrawled = pages
		}
		cw.mu.Unlock()
		if !cw.interactive {
			fmt.Fprintf(cw.outputWriter(), "CRAWLER COMPLETE urls=%d requests=%d\n", pages, payloadInt(e.Payload, "requests"))
			return nil
		}
		if cw.mode == "verbose" {
			fmt.Fprintf(cw.outputWriter(), "%sTRACE%s  %sCrawler completed: %d pages%s\n",
				cGhost, rst, cSlate, pages, rst)
		}

	// ── Health snapshots ────────────────────────────────────────────────
	case "oast_started":
		// OAST readiness is shown once in the scan session card. The provider
		// domain is intentionally omitted from normal mode because it is long,
		// transient and previously duplicated the same state above the card.
		if cw.mode == "verbose" {
			selection := safeTerminalText(fmt.Sprint(e.Payload["mode"]))
			if active := strings.TrimSpace(fmt.Sprint(e.Payload["active_server"])); active != "" && active != "<nil>" {
				selection += fmt.Sprintf(" server=%s priority=%d fallback=%t", safeTerminalText(active),
					payloadInt(e.Payload, "selected_priority"), payloadBool(e.Payload, "fallback_used"))
			}
			fmt.Fprintf(cw.outputWriter(), "%s╎%s  %sOAST provider%s  %s%s%s\n",
				cGhost, rst, cSlate, rst, cSilver,
				selection, rst)
		}

	case "oast_failed":
		fmt.Fprintf(cw.outputWriter(), "%s[OAST FAILED]%s  %s%s%s\n", bRose, rst, cRose, safeTerminalText(e.Message), rst)

	case "oast_probe_sent":
		cw.mu.Lock()
		cw.oastProbes++
		cw.mu.Unlock()
		if cw.mode == "verbose" {
			fmt.Fprintf(cw.outputWriter(), "%s[OAST SENT]%s  %s%s %s%s%s\n", cTeal, rst, cSilver,
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
		fmt.Fprintf(cw.outputWriter(), "%s[OAST DELIVERY GAP]%s  %s%s%s%s\n",
			bAmber, rst, cAmber, deliveryTarget, safeTerminalText(e.Message), rst)

	case "oast_callback_received":
		if !cw.acceptOASTCallback(e.Payload) {
			return nil
		}
		if !cw.interactive {
			fmt.Fprintf(cw.outputWriter(), "OAST CALLBACK protocol=%s class=%s url=%s parameter=%s\n",
				safeTerminalText(fmt.Sprint(e.Payload["protocol"])),
				safeTerminalText(fmt.Sprint(e.Payload["vuln_class"])),
				safeTerminalText(fmt.Sprint(e.Payload["endpoint"])),
				safeTerminalText(fmt.Sprint(e.Payload["parameter"])))
			return nil
		}
		fmt.Fprint(cw.outputWriter(), oastCallbackPanel(e.Payload))
		return nil

	case "waf_detected":
		fmt.Fprintf(cw.outputWriter(), "%s[WAF]%s  %s%s%s\n",
			bAmber, rst, cSilver, safeTerminalText(e.Message), rst)

	case "waf_traffic_adjusted":
		trafficText := trafficAdjustmentText(e.Payload)
		if !cw.acceptTrafficUpdate(trafficText) {
			return nil
		}
		fmt.Fprintf(cw.outputWriter(), "%s[TRAFFIC]%s  %s%s%s\n",
			bAmber, rst, cAmber, trafficText, rst)

	case "coverage_gap":
		cw.mu.Lock()
		cw.coverageGaps++
		cw.mu.Unlock()
		fmt.Fprintf(cw.outputWriter(), "%s[COVERAGE]%s  %s%s%s\n", bAmber, rst, cAmber, safeTerminalText(e.Message), rst)

	case "parameter_discovery_progress":
		completed := payloadInt(e.Payload, "completed")
		total := payloadInt(e.Payload, "total")
		if total <= 0 {
			return nil
		}
		cw.mu.Lock()
		cw.parameterCompleted = completed
		cw.parameterTotal = total
		if total > cw.maxDiscovered {
			cw.maxDiscovered = total
		}
		if completed > cw.maxTested {
			cw.maxTested = completed
		}
		cw.updateProgressLocked()
		cw.mu.Unlock()
		cw.writeRunningStatus()

	case "plugin_skipped":
		cw.mu.Lock()
		cw.skipped++
		cw.mu.Unlock()
		if cw.mode == "verbose" {
			fmt.Fprintf(cw.outputWriter(), "%s[SKIP]%s  %s%s%s  %s%s%s\n", cGhost, rst, cSilver,
				safeTerminalText(fmt.Sprint(e.Payload["module"])), rst, cSlate, safeTerminalText(e.Message), rst)
		}

	case "health_snapshot":
		if !cw.interactive {
			return nil
		}
		cw.mu.Lock()
		parameterDiscoveryActive := cw.lastPhase == "parameter_discovery" && cw.lastFinished != "parameter_discovery"
		cw.mu.Unlock()
		if parameterDiscoveryActive {
			return nil
		}
		discoveredVal, _ := e.Payload["endpoints_discovered"].(float64)
		testedVal, _ := e.Payload["endpoints_tested"].(float64)
		discovered := int(discoveredVal)
		tested := int(testedVal)
		requests := payloadInt(e.Payload, "request_count")
		payloadProbes := payloadInt(e.Payload, "payload_probes")
		heapMB := payloadInt(e.Payload, "heap_mb")
		processMemoryMB := payloadInt(e.Payload, "process_memory_mb")
		memoryLimitMB := payloadInt(e.Payload, "memory_limit_mb")
		requestRate := payloadFloat(e.Payload, "request_rate")

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

		cw.requests = max(cw.requests, requests)
		cw.payloadProbes = payloadProbes
		if processMemoryMB > 0 {
			cw.processMemoryMB = processMemoryMB
		} else {
			cw.processMemoryMB = heapMB
		}
		cw.requestRate = requestRate
		if requestRate > cw.peakRequestRate {
			cw.peakRequestRate = requestRate
		}
		if memoryLimitMB > 0 {
			cw.memoryLimitMB = memoryLimitMB
		}

		now := time.Now()
		if now.Sub(cw.lastSnapshot) < time.Second {
			cw.mu.Unlock()
			return nil
		}
		cw.lastSnapshot = now
		cw.updateProgressLocked()
		cw.updateETALocked(now)
		cw.mu.Unlock()
		cw.writeRunningStatus()

	// ── Report progress ─────────────────────────────────────────────────
	case "report_generation_progress":
		cw.mu.Lock()
		reportDone := cw.reportDone
		cw.mu.Unlock()
		if reportDone {
			return nil
		}
		percent, _ := e.Payload["percent"].(float64)
		section, _ := e.Payload["section"].(string)
		if !cw.interactive {
			return nil
		}
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
	skipped := cw.skipped
	requests := cw.requests
	payloadProbes := cw.payloadProbes
	oastProbes := cw.oastProbes
	oastCallbacks := cw.oastCallbacks
	coverageGaps := cw.coverageGaps
	sev := make(map[string]int)
	for k, v := range cw.severityMap {
		sev[k] = v
	}
	elapsed := cw.elapsed()
	interactive := cw.interactive
	mode := cw.mode
	cw.mu.Unlock()

	if !interactive || mode == "quiet" {
		fmt.Fprintf(os.Stderr, "RESULT duration=%s detected=%d confirmed=%d suppressed=%d skipped=%d requests=%d payload_probes=%d oast_hits=%d report=%s\n",
			elapsed, det, ver, suppressed, skipped, requests, payloadProbes, oastCallbacks, safeTerminalText(outPath))
		return
	}

	w := currentUIWidth()
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, panelTitle("SCAN COMPLETE", elapsed, w, cMint))
	fmt.Fprintln(os.Stderr, boxText(fmt.Sprintf(" %sFindings%s   %s%d confirmed%s  %s•%s  %s%d detected%s  %s•%s  %s%d suppressed%s",
		cSlate, rst, bMint, ver, rst, cGhost, rst, cSilver, det, rst, cGhost, rst, cSlate, suppressed, rst), w))
	fmt.Fprintln(os.Stderr, boxText(fmt.Sprintf(" %sCoverage%s   %s%d requests%s  %s•%s  %s%d payload probes%s  %s•%s  %s%d/%d OAST hits%s",
		cSlate, rst, cSilver, requests, rst, cGhost, rst, cSilver, payloadProbes, rst, cGhost, rst, cMint, oastCallbacks, oastProbes, rst), w))
	if coverageGaps > 0 {
		fmt.Fprintln(os.Stderr, boxText(fmt.Sprintf(" %sGaps%s       %s%d coverage warnings%s", cSlate, rst, cAmber, coverageGaps, rst), w))
	}
	if skipped > 0 {
		fmt.Fprintln(os.Stderr, boxText(fmt.Sprintf(" %sSkipped%s    %s%d module checks%s  %s(use --verbose for details)%s",
			cSlate, rst, cAmber, skipped, rst, cGhost, rst), w))
	}
	fmt.Fprintln(os.Stderr, panelDivider(w, cGhost))
	if det > 0 {
		crit := sev["critical"]
		high := sev["high"]
		med := sev["medium"]
		low := sev["low"]
		info := sev["info"]
		total := max(det, 1)

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

		barSize := min(24, max(12, w-30))
		for _, entry := range entries {
			if entry.count == 0 {
				continue
			}
			barWidth := (entry.count * barSize) / total
			if barWidth < 1 && entry.count > 0 {
				barWidth = 1
			}
			bar := entry.color + strings.Repeat("━", barWidth) + cGhost + strings.Repeat("─", barSize-barWidth) + rst
			value := fmt.Sprintf("%s %s  %s%d%s", entry.dot, bar, entry.color, entry.count, rst)
			fmt.Fprintln(os.Stderr, panelDetail(entry.name, value, w, entry.color))
		}
	} else {
		fmt.Fprintln(os.Stderr, boxText(fmt.Sprintf(" %s✓%s  %sNo vulnerabilities detected%s", cMint, rst, cMint, rst), w))
	}
	fmt.Fprintln(os.Stderr, panelDivider(w, cGhost))
	fmt.Fprintln(os.Stderr, panelDetail("Report", outPath, w, cIce))
	fmt.Fprintln(os.Stderr, panelBottom(w, cMint))
	fmt.Fprintln(os.Stderr)
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

func writeReport(path string, data []byte) error {
	path = strings.TrimSpace(path)
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if path == "" {
		return fmt.Errorf("report path is empty")
	}
	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create report directory: %w", err)
		}
	}
	if err := os.WriteFile(cleanPath, data, 0o644); err != nil {
		return err
	}
	return nil
}

func printCLIError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "\n%sERROR%s  %s%s%s\n", bRose, rst, cSilver, safeTerminalText(err.Error()), rst)
	fmt.Fprintf(os.Stderr, "%s       Run 'akca --help' for command usage.%s\n\n", cSlate, rst)
}

func printCLIStatus(level, message string) {
	label, color := "INFO", cIce
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "success", "ok", "ready":
		label, color = "READY", cMint
	case "warning", "warn":
		label, color = "WARN", cAmber
	case "error", "failed":
		label, color = "ERROR", cRose
	}
	fmt.Fprintf(os.Stderr, "%s%-5s%s  %s%s%s\n", color, label, rst, cSilver, safeTerminalText(message), rst)
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
	os.Exit(runCLI(os.Args[1:]))
}

func runCLI(args []string) (exitCode int) {
	configureTerminalStyle()
	defer func() {
		if recovered := recover(); recovered != nil {
			// Always reset styling before the fallback message. A renderer or
			// dependency panic must result in a clean terminal and non-zero exit,
			// never a raw stack dump in normal operation.
			fmt.Fprint(os.Stderr, ansiReset)
			fmt.Fprintf(os.Stderr, "\nERROR  %s stopped safely after an internal error: %s\n", branding.ProductName, safeTerminalText(fmt.Sprint(recovered)))
			fmt.Fprintln(os.Stderr, "       Run again with --verbose and report the preceding operation if the problem repeats.")
			exitCode = 1
		}
	}()

	if len(args) > 0 {
		switch strings.ToLower(strings.TrimSpace(args[0])) {
		case "scan":
			return runScanCommand(args[1:])
		case "replay":
			return runReplayCommand(args[1:])
		case "benchmark":
			return runBenchmarkCommand(args[1:])
		case "help":
			printDetailedUsage()
			return 0
		case "version":
			printVersion()
			return 0
		}
	}
	return runScanCommand(args)
}

func runScanCommand(args []string) int {
	args = normalizeScanArgs(args)
	var targetURL string
	var targetDomain string
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
	var wafEvasion bool
	var noWAFEvasion bool
	var rateLimit float64
	var perHostRate float64
	var concurrency int
	var perHostConcurrency int
	var maxPages int
	var maxEndpoints int
	var maxDepth int
	var crawlerBudget int
	var requestBudget int
	var timeBudget time.Duration
	var memoryLimitMB int
	var includeLinkedAPISubdomains bool
	var showVersion bool
	var showHelp bool
	var showShortHelp bool
	var scanID string
	var scanMode string
	var verbose bool
	var quiet bool

	fs := flag.NewFlagSet("akca", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&targetURL, "url", "", "")
	fs.StringVar(&targetURL, "u", "", "")
	fs.StringVar(&targetDomain, "domain", "", "")
	fs.StringVar(&targetDomain, "d", "", "")
	fs.StringVar(&proxyURL, "proxy", "", "")
	fs.StringVar(&proxyURL, "p", "", "")
	fs.BoolVar(&insecureTLS, "insecure", false, "")
	fs.BoolVar(&insecureTLS, "k", false, "")
	var resumeID string
	fs.StringVar(&resumeID, "resume", "", "")
	fs.StringVar(&resumeID, "r", "", "")
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
	fs.BoolVar(&wafEvasion, "waf-evasion", false, "")
	fs.BoolVar(&noWAFEvasion, "no-waf-evasion", false, "")
	fs.IntVar(&maxPages, "max-pages", 0, "")
	fs.IntVar(&maxEndpoints, "max-endpoints", 0, "")
	fs.IntVar(&maxDepth, "max-depth", 0, "")
	fs.IntVar(&crawlerBudget, "crawler-budget", 0, "")
	fs.IntVar(&requestBudget, "request-budget", 0, "")
	fs.DurationVar(&timeBudget, "time-budget", 0, "")
	fs.IntVar(&memoryLimitMB, "memory-limit", 0, "")
	fs.BoolVar(&includeLinkedAPISubdomains, "include-linked-api-subdomains", false, "")
	fs.Float64Var(&rateLimit, "rate-limit", 0, "")
	fs.Float64Var(&perHostRate, "per-host-rate", 0, "")
	fs.IntVar(&concurrency, "concurrency", 0, "")
	fs.IntVar(&perHostConcurrency, "per-host-concurrency", 0, "")
	fs.StringVar(&scanID, "scan-id", "", "")
	fs.BoolVar(&showVersion, "version", false, "")
	fs.BoolVar(&showHelp, "help", false, "")
	fs.BoolVar(&showShortHelp, "h", false, "")
	fs.StringVar(&scanMode, "mode", "full", "")
	fs.StringVar(&scanMode, "m", "full", "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&verbose, "v", false, "")
	fs.BoolVar(&quiet, "quiet", false, "")
	fs.BoolVar(&quiet, "q", false, "")

	// Parsing errors are rendered below with Neon Pulse semantics. Keeping the
	// FlagSet usage hook silent prevents an unknown flag from dumping the full
	// help screen before the concise error.
	fs.Usage = func() {}
	if err := fs.Parse(args); err != nil {
		printCLIError(err)
		return 2
	}

	if flagWasSet(fs, "mode") || flagWasSet(fs, "m") {
		if _, _, _, err := config.ResolveScanModes(scanMode); err != nil {
			printCLIError(err)
			return 2
		}
	}

	if showVersion {
		printVersion()
		return 0
	}

	if flagWasSet(fs, "help") {
		printDetailedUsage()
		return 0
	}

	if flagWasSet(fs, "h") {
		printDetailedUsage()
		return 0
	}

	if targetURL == "" && targetDomain == "" && resumeID == "" && fs.NArg() == 0 {
		printShortUsage()
		return 0
	}

	// Allow positional argument: akca domain.com
	if targetURL == "" && targetDomain == "" && resumeID == "" && fs.NArg() > 0 {
		targetURL = fs.Arg(0)
		if fs.NArg() > 1 {
			printCLIError(fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args()[1:], " ")))
			return 2
		}
	} else if fs.NArg() > 0 {
		printCLIError(fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " ")))
		return 2
	}
	targetURL = strings.TrimSpace(targetURL)
	targetDomain = strings.TrimSpace(targetDomain)
	resumeID = strings.TrimSpace(resumeID)

	providedSources := 0
	for _, value := range []string{targetURL, targetDomain, resumeID} {
		if value != "" {
			providedSources++
		}
	}
	if providedSources > 1 {
		printCLIError(fmt.Errorf("choose exactly one of --url, --domain, or --resume"))
		return 2
	}
	if targetURL == "" && targetDomain == "" && resumeID == "" {
		printCLIError(fmt.Errorf("either target URL (-u), target domain (-d), or --resume (-r) is required"))
		return 1
	}
	wafEvasionSet := flagWasSet(fs, "waf-evasion")
	noWAFEvasionSet := flagWasSet(fs, "no-waf-evasion")
	if wafEvasionSet && noWAFEvasionSet {
		printCLIError(fmt.Errorf("--waf-evasion and --no-waf-evasion cannot be used together"))
		return 2
	}
	if noOAST && strings.TrimSpace(oastServer) != "" {
		printCLIError(fmt.Errorf("--no-oast and --oast-server cannot be used together"))
		return 2
	}
	if resumeID != "" && strings.TrimSpace(scanID) != "" {
		printCLIError(fmt.Errorf("--resume already identifies the scan; remove --scan-id"))
		return 2
	}
	if flagWasSet(fs, "rate-limit") && (rateLimit <= 0 || math.IsNaN(rateLimit) || math.IsInf(rateLimit, 0)) {
		printCLIError(fmt.Errorf("--rate-limit must be greater than zero"))
		return 2
	}
	if flagWasSet(fs, "per-host-rate") && (perHostRate <= 0 || math.IsNaN(perHostRate) || math.IsInf(perHostRate, 0)) {
		printCLIError(fmt.Errorf("--per-host-rate must be greater than zero"))
		return 2
	}
	if flagWasSet(fs, "concurrency") && concurrency <= 0 {
		printCLIError(fmt.Errorf("--concurrency must be greater than zero"))
		return 2
	}
	if flagWasSet(fs, "per-host-concurrency") && perHostConcurrency <= 0 {
		printCLIError(fmt.Errorf("--per-host-concurrency must be greater than zero"))
		return 2
	}
	if flagWasSet(fs, "max-pages") && maxPages < 0 {
		printCLIError(fmt.Errorf("--max-pages cannot be negative"))
		return 2
	}
	if flagWasSet(fs, "max-endpoints") && maxEndpoints < 0 {
		printCLIError(fmt.Errorf("--max-endpoints cannot be negative"))
		return 2
	}
	if flagWasSet(fs, "max-depth") && maxDepth < 0 {
		printCLIError(fmt.Errorf("--max-depth cannot be negative"))
		return 2
	}
	if flagWasSet(fs, "crawler-budget") && crawlerBudget < 0 {
		printCLIError(fmt.Errorf("--crawler-budget cannot be negative"))
		return 2
	}
	if flagWasSet(fs, "request-budget") && requestBudget < 0 {
		printCLIError(fmt.Errorf("--request-budget cannot be negative"))
		return 2
	}
	if flagWasSet(fs, "time-budget") && timeBudget < 0 {
		printCLIError(fmt.Errorf("--time-budget cannot be negative"))
		return 2
	}
	if flagWasSet(fs, "memory-limit") && memoryLimitMB < 0 {
		printCLIError(fmt.Errorf("--memory-limit cannot be negative"))
		return 2
	}
	if oastWait < 0 {
		printCLIError(fmt.Errorf("--oast-wait cannot be negative"))
		return 2
	}
	if verbose && quiet {
		printCLIError(fmt.Errorf("--verbose and --quiet cannot be used together"))
		return 2
	}
	customHeaders, err := parseHeaders(headers)
	if err != nil {
		printCLIError(err)
		return 2
	}

	repFmt, err := normalizeFormat(outputFormat)
	if err != nil {
		printCLIError(err)
		return 2
	}

	if !quiet {
		if interactiveOutput() {
			printBanner()
		} else {
			printCompactBanner()
		}
	}

	// ── Bootstrap data directory ────────────────────────────────────────
	if _, err := storage.BootstrapDataDir(); err != nil {
		printCLIError(fmt.Errorf("data directory initialization failed: %w", err))
		return 1
	}

	// ── Create engine ───────────────────────────────────────────────────
	cwMode := "normal"
	if verbose {
		cwMode = "verbose"
	} else if quiet {
		cwMode = "quiet"
	}
	cw := NewConsoleWriterMode(cwMode)
	engine, err := app.New(cw)
	if err != nil {
		printCLIError(fmt.Errorf("engine initialization failed: %w", err))
		return 1
	}
	defer engine.Close()

	// ── Build scan config ───────────────────────────────────────────────
	cfg := config.DefaultScanConfig()
	cfg.ScanID = strings.TrimSpace(scanID)
	if cfg.ScanID == "" {
		cfg.ScanID = fmt.Sprintf("scan-%d", time.Now().Unix())
	}

	var initialTargets []string
	if targetDomain != "" {
		if !quiet {
			printCLIStatus("info", "Discovering passive subdomains for "+targetDomain)
		}
		subEng := subdomain.New()
		ctxSub, cancelSub := context.WithTimeout(context.Background(), 120*time.Second)
		_, liveURLs, err := subEng.DiscoverAndProbe(ctxSub, targetDomain)
		cancelSub()

		if err != nil || len(liveURLs) == 0 {
			if !quiet {
				printCLIStatus("warn", "No live subdomains found; probing the root domain")
			}
			initialTargets = []string{"https://" + targetDomain, "http://" + targetDomain}
		} else {
			if !quiet {
				printCLIStatus("ready", fmt.Sprintf("Found %d live subdomain target(s)", len(liveURLs)))
			}
			for _, u := range liveURLs {
				if verbose {
					fmt.Fprintf(os.Stderr, "       %s%s%s\n", cIce, safeTerminalText(u), rst)
				}
			}
			initialTargets = liveURLs
		}
	} else {
		initialTargets = []string{targetURL}
	}
	cfg.Targets = initialTargets
	// In domain mode, record subdomain count so EffectiveMaxPages can scale
	// the crawl budget proportionally across all live subdomains.
	if targetDomain != "" && len(initialTargets) > 1 {
		cfg.SubdomainCount = len(initialTargets)
	}
	cfg.APIImportFiles = append([]string(nil), apiSpecs...)
	if err := config.ApplyScanModes(&cfg, scanMode); err != nil {
		printCLIError(err)
		return 2
	}
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
	if wafEvasionSet {
		cfg.EnableWAFBypassHeaders = wafEvasion
		cfg.Explicit.EnableWAFBypassHeaders = true
	}
	if noWAFEvasionSet {
		cfg.EnableWAFBypassHeaders = !noWAFEvasion
		cfg.Explicit.EnableWAFBypassHeaders = true
	}
	if noOAST {
		cfg.Explicit.EnableOAST = true
	}
	if noFuzzing {
		cfg.Explicit.EnableFuzzing = true
	}
	if noJS {
		cfg.Explicit.EnableJSAnalysis = true
	}
	if flagWasSet(fs, "rate-limit") {
		cfg.GlobalRateLimit = rateLimit
		cfg.Explicit.GlobalRateLimit = true
	}
	if flagWasSet(fs, "per-host-rate") {
		cfg.PerHostRateLimit = perHostRate
		cfg.Explicit.PerHostRateLimit = true
	}
	if flagWasSet(fs, "concurrency") {
		cfg.MaxConcurrency = concurrency
		cfg.Explicit.MaxConcurrency = true
	}
	if flagWasSet(fs, "per-host-concurrency") {
		cfg.PerHostConcurrency = perHostConcurrency
		cfg.Explicit.PerHostConcurrency = true
	}
	if flagWasSet(fs, "max-pages") {
		cfg.MaxPages = maxPages
		cfg.Explicit.MaxPages = true
	}
	if flagWasSet(fs, "max-endpoints") {
		cfg.MaxEndpoints = maxEndpoints
		cfg.Explicit.MaxEndpoints = true
	}
	if flagWasSet(fs, "max-depth") {
		cfg.MaxDepth = maxDepth
		cfg.Explicit.MaxDepth = true
	}
	if flagWasSet(fs, "crawler-budget") {
		cfg.CrawlerRequestBudget = crawlerBudget
		cfg.Explicit.CrawlerRequestBudget = true
	}
	if flagWasSet(fs, "request-budget") {
		cfg.RequestBudget = requestBudget
		cfg.Explicit.RequestBudget = true
	}
	if flagWasSet(fs, "time-budget") {
		cfg.TimeBudget = timeBudget
		cfg.Explicit.TimeBudget = true
	}
	if flagWasSet(fs, "memory-limit") {
		cfg.MaxMemoryMB = memoryLimitMB
	}
	if includeLinkedAPISubdomains {
		cfg.IncludeLinkedAPISubdomains = true
	}

	// Browser setup can download a runtime, so do it only after mode/profile
	// resolution proves that headless coverage is actually enabled. Passive
	// scans and non-scan commands now start immediately without Chromium.
	if cfg.EnableHeadlessCrawler {
		if browserPath, downloaded, browserErr := browserpool.EnsureBrowser(); browserErr != nil {
			printCLIStatus("warn", fmt.Sprintf("Browser automation unavailable: %v", browserErr))
			printCLIStatus("info", "Continuing with HTTP coverage; DOM execution checks will be skipped")
		} else if downloaded && !quiet {
			printCLIStatus("ready", "Chromium installed automatically: "+safeTerminalText(browserPath))
		}
	}

	// ── Start scan or Resume from checkpoint ───────────────────────────
	if resumeID != "" {
		cfg.ScanID = resumeID
		cfgBytes, marshalErr := json.Marshal(cfg)
		if marshalErr != nil {
			printCLIError(fmt.Errorf("could not prepare resume configuration: %w", marshalErr))
			return 1
		}
		if err := engine.ResumeScan(app.CommandInput{Config: cfgBytes}); err != nil {
			printCLIError(fmt.Errorf("resume failed: %w", err))
			return 1
		}
	} else {
		if err := engine.StartScan(cfg); err != nil {
			printCLIError(fmt.Errorf("scan failed to start: %w", err))
			return 1
		}
	}

	// ── Graceful shutdown on SIGINT/SIGTERM ──────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signalDone := make(chan struct{})
	interrupted := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	defer close(signalDone)
	go func() {
		select {
		case <-sigCh:
			close(interrupted)
			cw.renderMu.Lock()
			cw.closeProgressLine()
			printCLIStatus("warn", "Interrupt received; stopping gracefully")
			cw.renderMu.Unlock()
			_ = engine.StopScan()
		case <-signalDone:
		}
	}()

	// ── Wait for scan completion ────────────────────────────────────────
	scanErr := engine.WaitScanDone(context.Background())
	if scanErr != nil && scanErr != context.Canceled {
		cw.closeProgressLine()
		printCLIStatus("error", "Scan error: "+scanErr.Error())
	}

	// ── Generate report ─────────────────────────────────────────────────
	cw.closeProgressLine()
	if !quiet {
		if cw.interactive {
			fmt.Fprintln(os.Stderr)
			printCLIStatus("info", fmt.Sprintf("Generating %s report", repFmt))
		} else {
			fmt.Fprintf(os.Stderr, "REPORT START format=%s\n", repFmt)
		}
	}

	reportOpts := report.Options{
		ScanID:   cfg.ScanID,
		Template: report.TemplateInternal,
		Format:   repFmt,
		Partial:  scanErr != nil,
		Redact:   false,
	}

	reportData, err := engine.GenerateReport(reportOpts)
	if err != nil {
		cw.closeProgressLine()
		printCLIError(fmt.Errorf("report generation failed: %w", err))
		return 1
	}

	outPath := outputFilePath
	if outPath == "" {
		ext := string(repFmt)
		if repFmt == report.FormatMarkdown {
			ext = "md"
		}
		outPath = fmt.Sprintf("akca-report-%s.%s", cfg.ScanID, ext)
	}

	if err := writeReport(outPath, reportData); err != nil {
		cw.closeProgressLine()
		printCLIError(fmt.Errorf("failed to save report: %w", err))
		return 1
	}
	cw.mu.Lock()
	cw.reportDone = true
	cw.mu.Unlock()
	cw.closeProgressLine()
	if !quiet && !cw.interactive {
		fmt.Fprintf(os.Stderr, "REPORT COMPLETE path=%s\n", safeTerminalText(outPath))
	}

	// ── Print summary ───────────────────────────────────────────────────
	cw.closeProgressLine()
	printSummary(cw, outPath)
	select {
	case <-interrupted:
		return 130
	default:
	}
	if scanErr != nil && scanErr != context.Canceled {
		return 1
	}
	return 0
}

func runReplayCommand(args []string) int {
	fs := flag.NewFlagSet("akca replay", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var findingID int64
	var verbose bool
	var help bool
	fs.Int64Var(&findingID, "finding", 0, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&verbose, "v", false, "")
	fs.BoolVar(&help, "help", false, "")
	fs.BoolVar(&help, "h", false, "")
	if err := fs.Parse(args); err != nil {
		printCLIError(fmt.Errorf("replay: %w", err))
		return 2
	}
	if help {
		fmt.Fprintln(os.Stderr, "Usage: akca replay --finding <id> [--verbose]")
		fmt.Fprintln(os.Stderr, "Replays stored request evidence and returns the verification result as JSON.")
		return 0
	}
	if findingID <= 0 || fs.NArg() > 0 {
		printCLIError(fmt.Errorf("replay requires --finding with a positive stored finding ID"))
		return 2
	}
	if _, err := storage.BootstrapDataDir(); err != nil {
		printCLIError(fmt.Errorf("replay data directory: %w", err))
		return 1
	}
	replayCWMode := "normal"
	if verbose {
		replayCWMode = "verbose"
	}
	engine, err := app.New(NewConsoleWriterMode(replayCWMode))
	if err != nil {
		printCLIError(fmt.Errorf("replay initialization: %w", err))
		return 1
	}
	defer engine.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	result, err := engine.ReplayFinding(ctx, findingID)
	if err != nil {
		printCLIError(fmt.Errorf("replay failed: %w", err))
		return 1
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		printCLIError(fmt.Errorf("replay result encoding failed: %w", err))
		return 1
	}
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
	var help bool
	fs.StringVar(&dbPath, "db", "", "")
	fs.StringVar(&outputPath, "output", "", "")
	fs.BoolVar(&strict, "strict", false, "")
	fs.BoolVar(&help, "help", false, "")
	fs.BoolVar(&help, "h", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		if err != nil {
			printCLIError(fmt.Errorf("benchmark: %w", err))
		}
		fmt.Fprintln(os.Stderr, "Usage: akca benchmark [--db <path>] [--output <json>] [--strict]")
		return 2
	}
	if help {
		fmt.Fprintln(os.Stderr, "Usage: akca benchmark [--db <path>] [--output <json>] [--strict]")
		fmt.Fprintln(os.Stderr, "Runs observed scanner quality gates; --strict returns exit code 3 when a gate fails.")
		return 0
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
