// Package php2shell performs non-invasive PHP2Shell exposure assessment.
// Banners are inventory evidence, never proof of code execution or patch state.
package php2shell

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const Advisory = "https://www.php.net/archive/2026.php#2026-10-21-5"

type VersionEvidence struct {
	Version string `json:"version"`
	Source  string `json:"source"`
	Status  string `json:"status"`
	FixedIn string `json:"fixed_in,omitempty"`
}

type Assessment struct {
	Endpoint          string            `json:"endpoint"`
	Status            string            `json:"status"`
	Reason            string            `json:"reason"`
	PHPDetected       bool              `json:"php_detected"`
	Versions          []VersionEvidence `json:"versions,omitempty"`
	CVEs              []string          `json:"cves"`
	Reference         string            `json:"reference"`
	ExploitVerified   bool              `json:"exploit_verified"`
	Remediation       string            `json:"remediation"`
	ActiveCrashSignal bool              `json:"active_crash_signal,omitempty"`
	ActiveProbeMiB    int               `json:"active_probe_mib,omitempty"`
	ActiveStatus      int               `json:"active_status,omitempty"`
}

func (a *Assessment) RecordActiveSignal(statusCode, sizeMiB int, memoryError bool) {
	if a == nil {
		return
	}
	a.ActiveStatus = statusCode
	a.ActiveProbeMiB = sizeMiB
	if memoryError {
		a.ActiveCrashSignal = true
		a.Status = "active_signal"
		a.Reason = "The active probe produced the PHP memory-exhaustion error signature. This is a strong crash signal, not proof of RCE; inspect worker logs, SAPI, build/backport status and repeat only in the authorized lab."
	}
}

var bannerVersion = regexp.MustCompile(`(?i)\bphp(?:-fpm)?[/ ]([0-9]+\.[0-9]+\.[0-9]+[a-z0-9.+~_-]*)`)
var phpBanner = regexp.MustCompile(`(?i)\bphp(?:-fpm)?\b`)
var stableVersion = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$`)
var prerelease = regexp.MustCompile(`(?i)^[-_.]?(?:alpha|beta|rc|dev)`)

// Inspect consumes only response metadata. Body mentions, .php paths and
// PHPSESSID cookies cannot establish an installed PHP version or a patch.
func Inspect(endpoint string, statusCode int, headers map[string]string) Assessment {
	a := Assessment{
		Endpoint: endpoint, Status: "unknown",
		Reason: "PHP version is unavailable; PHP2Shell exposure cannot be determined (not a clean result).",
		CVEs:   []string{"CVE-2026-109618", "CVE-2026-109619"}, Reference: Advisory,
		Remediation: "Verify the installed package/build with the vendor. Update to PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 or a vendor-confirmed patched build; restart all PHP workers. Banner versions alone cannot establish backport status.",
	}
	if statusCode <= 0 {
		a.Reason = "No observed HTTP response; PHP2Shell exposure cannot be determined."
		return a
	}
	if statusCode == 401 || statusCode == 403 || statusCode == 407 || statusCode == 429 || statusCode >= 500 {
		a.Status = "blocked"
		a.Reason = fmt.Sprintf("HTTP %d response is not reliable application evidence; PHP2Shell exposure cannot be determined.", statusCode)
		return a
	}
	seen := map[string]bool{}
	// Fixed iteration order keeps assessment and tests deterministic even when
	// the HTTP client stores response headers in a map.
	for _, name := range []string{"X-Powered-By", "Server"} {
		var values []string
		for key, value := range headers {
			if strings.EqualFold(key, name) {
				values = append(values, value)
			}
		}
		for _, value := range values {
			a.PHPDetected = a.PHPDetected || phpBanner.MatchString(value)
			for _, match := range bannerVersion.FindAllStringSubmatch(value, -1) {
				version := strings.TrimRight(match[1], ".")
				if seen[name+"|"+version] {
					continue
				}
				seen[name+"|"+version] = true
				status, fixed := classifyVersion(version)
				a.Versions = append(a.Versions, VersionEvidence{Version: version, Source: name, Status: status, FixedIn: fixed})
			}
		}
	}
	if u, err := url.Parse(endpoint); err == nil && strings.HasSuffix(strings.ToLower(u.Path), ".php") {
		a.PHPDetected = true // A hint only; never an installed-version claim.
	}
	if len(a.Versions) == 0 {
		return a
	}
	a.Status = a.Versions[0].Status
	for _, version := range a.Versions[1:] {
		if version.Status != a.Status {
			a.Status = "unknown"
			break
		}
	}
	switch a.Status {
	case "potential":
		a.Reason = "Advertised PHP version precedes the upstream PHP2Shell fixes. Potential exposure only: vendor backports, SAPI and runtime configuration are unverified; RCE was not tested."
	case "fixed_version_observed":
		a.Reason = "Advertised PHP version meets an upstream PHP2Shell fixed release. This does not verify the deployed build, worker restart or other backends and is not proof the target is safe."
	case "manual_review":
		a.Reason = "Legacy PHP version observed. Vendor backport/build verification or an upgrade is required; the banner cannot establish PHP2Shell patch state."
	default:
		a.Reason = "Unrecognized, prerelease or conflicting PHP version evidence; PHP2Shell exposure cannot be determined."
	}
	return a
}

func classifyVersion(version string) (string, string) {
	m := stableVersion.FindStringSubmatch(version)
	if len(m) != 5 {
		return "unknown", ""
	}
	n := [3]int{}
	for i := range n {
		value, err := strconv.Atoi(m[i+1])
		if err != nil {
			return "unknown", ""
		}
		n[i] = value
	}
	if n[0] < 8 || (n[0] == 8 && n[1] < 2) {
		return "manual_review", ""
	}
	fixes := map[int]int{2: 35, 3: 36, 4: 27, 5: 12}
	patch, known := fixes[n[1]]
	if n[0] != 8 || !known {
		return "unknown", ""
	}
	fixed := fmt.Sprintf("8.%d.%d", n[1], patch)
	if n[2] < patch {
		return "potential", fixed
	}
	if n[2] == patch && prerelease.MatchString(m[4]) {
		return "potential", fixed
	}
	return "fixed_version_observed", fixed
}

func (a Assessment) Summary() string {
	var versions []string
	for _, v := range a.Versions {
		versions = append(versions, v.Version+" ("+v.Source+")")
	}
	detail := "version unavailable"
	if len(versions) > 0 {
		detail = strings.Join(versions, ", ")
	}
	return fmt.Sprintf("PHP2Shell [%s] %s | %s | CVE-2026-109618, CVE-2026-109619 | %s", a.Status, a.Endpoint, detail, a.Reason)
}
