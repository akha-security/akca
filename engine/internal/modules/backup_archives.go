package modules

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type binaryMagic struct {
	name       string
	magicBytes []byte
}

type archiveProbeTask struct {
	path string
	ext  string
}

type archiveProbeResult struct {
	finding      *ModuleFinding
	signal       string
	promising    bool
	blocked      bool
	blockedCause string
}

const (
	archiveRootCanaryProbes  = 24
	archiveRouteCanaryProbes = 12
	archiveExpandedProbes    = 96
)

var archiveMagicSignatures = []binaryMagic{
	{name: "ZIP Archive", magicBytes: parseHex("504B0304")},
	{name: "7z Archive", magicBytes: parseHex("377ABCAF271C")},
	{name: "RAR Archive v1.5", magicBytes: parseHex("526172211A0700")},
	{name: "RAR Archive v5.0", magicBytes: parseHex("526172211A070100")},
	{name: "GZ / Tar.Gz Archive", magicBytes: parseHex("1F8B")},
	{name: "BZ2 Archive", magicBytes: parseHex("314159265359")},
	{name: "XZ Archive", magicBytes: parseHex("FD377A585A0000")},
	{name: "SQLite Database", magicBytes: parseHex("53514c69746520666f726d6174203300")},
	{name: "TAR Archive", magicBytes: parseHex("7573746172202000")},
	{name: "TAR Archive v2", magicBytes: parseHex("7573746172003030")},
	{name: "LZ Archive", magicBytes: parseHex("4C5A4950")},
	{name: "Z Archive", magicBytes: parseHex("1F9D")},
}

func parseHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func (r *Runner) runBackupArchives(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("backup_archives", target); !ok {
		r.emitSkip("backup_archives", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil || u.Host == "" {
		return nil
	}
	originTarget, ok := originScanTarget(target)
	if !ok {
		return nil
	}
	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	unlockOrigin := r.lockBackupArchiveOrigin(baseURL)
	defer unlockOrigin()

	hostname := strings.ToLower(u.Hostname())
	parts := strings.Split(hostname, ".")

	domainName := hostname
	subdomainName := parts[0]
	if len(parts) >= 2 {
		domainName = parts[len(parts)-2]
	}

	currentYear := fmt.Sprintf("%d", time.Now().Year())

	// Root candidates are intentionally scanned once per origin. Repeating this
	// dictionary for every discovered route prefix was the dominant source of
	// archive-scan amplification.
	rootCandidates := []string{
		hostname,
		domainName,
		subdomainName,
		currentYear,
		fmt.Sprintf("%d", time.Now().Year()-1),
		"ROOT", "wwwroot", "htdocs", "www", "html", "web", "webapps", "public", "public_html",
		"uploads", "website", "api", "test", "app", "backup", "backup_1", "backup_2", "backup_3", "backup_4", "backups",
		"bin", "temp", "bak", "db", "sql", "dump", "database", "Release", "inetpub", "package", "site",
		"tmp", "data", "admin", "upload", "src", "source", "old", "Scripts", "static", "assets", "dist",
		"build", "frontend", "backend", "client", "server", "services", "controllers", "models",
		"config", "database", "core", "modules", "components", "dashboard", "portal", "lib", "vendor",
		"includes", "middleware", "handlers", "views",
	}

	routeCandidates := make(map[string]struct{})
	var directPathCandidates []string

	// Dynamic Path Segment & Subpath Extraction (e.g., /v1/checkout/main.js -> "v1", "checkout", "main")
	if u.Path != "" && u.Path != "/" {
		segments := strings.Split(strings.Trim(u.Path, "/"), "/")
		accumulated := ""
		for _, seg := range segments {
			cleanSeg := strings.TrimSpace(seg)
			if cleanSeg == "" {
				continue
			}
			rawName := cleanSeg
			if dotIdx := strings.LastIndex(cleanSeg, "."); dotIdx > 0 {
				rawName = cleanSeg[:dotIdx]
			}
			for _, candidate := range []string{rawName, cleanSeg, rawName + "_backup", rawName + "-old", rawName + "." + currentYear} {
				routeCandidates[candidate] = struct{}{}
			}

			accumulated += "/" + cleanSeg
			directPathCandidates = append(directPathCandidates, accumulated)
		}
	}

	runRootDictionary := r.moduleWorkOnce("backup_archives_root", baseURL)
	routePrefix := firstRoutePrefix(u.Path)
	baseline, baselineErr := r.cachedEmptyProbe(ctx, originTarget)
	if baselineErr != nil {
		return nil
	}
	seenPath := map[string]struct{}{}
	probeTasks := make([]archiveProbeTask, 0, len(rootCandidates)*6)
	addProbe := func(path, ext string) {
		if _, exists := seenPath[path]; exists {
			return
		}
		seenPath[path] = struct{}{}
		targetURL := baseURL + path
		// Path candidates can overlap (for example /news.zip may be derived both
		// from a segment and from its accumulated path). Deduplicate them across
		// every route and HTTP method handled by this runner.
		if !r.moduleWorkOnce("backup_archives_probe", targetURL) {
			return
		}
		probeTasks = append(probeTasks, archiveProbeTask{path: path, ext: ext})
	}

	// 1. Queue the broad root-level archive dictionary exactly once per origin.
	if runRootDictionary {
		for _, fname := range rootCandidates {
			for _, ext := range archiveExtensionsForCandidate(fname) {
				addProbe(fmt.Sprintf("/%s.%s", fname, ext), ext)
			}
		}
	}

	// 2. Route-derived candidates remain covered, but they stay under their
	// application prefix instead of multiplying the origin-wide root list.
	if routePrefix != "/" {
		for fname := range routeCandidates {
			for _, ext := range archiveExtensionsForCandidate(fname) {
				addProbe(fmt.Sprintf("%s/%s.%s", routePrefix, fname, ext), ext)
			}
		}
		for _, subPath := range directPathCandidates {
			for _, ext := range archiveExtensionsForCandidate(subPath) {
				addProbe(fmt.Sprintf("%s.%s", subPath, ext), ext)
			}
		}
	}
	if len(probeTasks) == 0 {
		return nil
	}

	preferredPaths := []string{
		"/backup.zip", "/backup.tar.gz", "/" + hostname + ".zip", "/" + domainName + ".zip",
		"/site.zip", "/www.zip", "/" + currentYear + ".zip", "/database.sql.gz", "/db.sql.gz", "/dump.sql.gz",
	}
	if cleanPath := strings.TrimRight(u.Path, "/"); cleanPath != "" {
		preferredPaths = append(preferredPaths, cleanPath+".bak", cleanPath+".old", cleanPath+".zip")
	}
	probeTasks = prioritizeArchiveProbeTasks(probeTasks, preferredPaths)

	// Archive enumeration is deliberately single-lane per origin. A short,
	// high-yield canary stage avoids turning a uniform 404 surface into hundreds
	// of requests. Concrete route hints or archive-like responses unlock a
	// bounded expansion stage.
	probeLimit := archiveRouteCanaryProbes
	if runRootDictionary {
		probeLimit = archiveRootCanaryProbes
	}
	if archivePathSuggestsBackup(u.Path) {
		probeLimit = archiveExpandedProbes
	}
	probeLimit = min(probeLimit, len(probeTasks))
	var out []ModuleFinding
	for index, task := range probeTasks {
		if index >= probeLimit || ctx.Err() != nil {
			break
		}
		if index > 0 {
			if err := waitArchiveProbePace(ctx, r.backupArchiveProbeDelay()); err != nil {
				break
			}
		}
		result := r.probeArchiveCandidate(ctx, originTarget, baseURL, task, baseline)
		if result.blocked {
			r.emitOnce("backup_archives_blocked:"+baseURL, "coverage_gap",
				"Backup archive enumeration stopped after target throttling or WAF blocking",
				map[string]interface{}{"scan_id": r.scanID, "module": "backup_archives", "origin": baseURL, "reason": result.blockedCause})
			break
		}
		if result.promising && probeLimit < archiveExpandedProbes {
			probeLimit = min(archiveExpandedProbes, len(probeTasks))
		}
		if result.finding != nil && r.recordFinding(ctx, &out, result.finding, "backup_archives", result.signal) {
			// One verified public archive proves the exposure. Do not keep spraying
			// sibling names after impact is established.
			break
		}
	}
	return out
}

func (r *Runner) probeArchiveCandidate(ctx context.Context, originTarget ScanTarget, baseURL string,
	task archiveProbeTask, baseline httpclient.RequestResponse) archiveProbeResult {
	targetURL := baseURL + task.path
	probeTarget := originTarget
	probeTarget.EndpointURL = targetURL
	probeTarget.Parameter = ""
	probeTarget.Location = ""

	rr, err := r.probeHeadersOnlyForModule(ctx, "backup_archives", probeTarget, map[string]string{
		"Range": "bytes=0-511", "Accept-Encoding": "identity",
	})
	if err != nil {
		return archiveProbeResult{}
	}
	if archiveBlockedResponse(rr.Response) {
		return archiveProbeResult{blocked: true, blockedCause: fmt.Sprintf("HTTP %d block response", rr.Response.StatusCode)}
	}
	if rr.Response.StatusCode != http.StatusOK && rr.Response.StatusCode != http.StatusPartialContent {
		return archiveProbeResult{}
	}
	if rr.Response.Redirected && isRedirectedAway(rr, targetURL) {
		return archiveProbeResult{}
	}
	if isHTMLResponse(rr.Response) {
		return archiveProbeResult{}
	}
	promising := archiveLikeResponse(rr.Response)

	// Strict Binary Magic Bytes Matching (Zero False Positive Proof Contract)
	bodyBytes := []byte(rr.Response.Body)
	if len(bodyBytes) < 4 {
		return archiveProbeResult{promising: promising}
	}

	var matchedMagic *binaryMagic
	for _, m := range archiveMagicSignatures {
		if len(m.magicBytes) > 0 && len(bodyBytes) >= len(m.magicBytes) {
			if bytesHasPrefix(bodyBytes, m.magicBytes) || bytesContains(bodyBytes[:minInt(len(bodyBytes), 512)], m.magicBytes) {
				matchedMagic = &m
				break
			}
		}
	}

	if matchedMagic != nil {
		signal := fmt.Sprintf("compressed_backup_disclosure_%s", strings.ReplaceAll(strings.ToLower(task.ext), ".", "_"))
		p := defaultPayload("backup_archives", task.path, task.path, signal)
		f := r.verifyAndBuild(ctx, "backup_archives", probeTarget, p, baseline, rr, signal, false, false, "", "")
		if f != nil {
			f.Title = fmt.Sprintf("Exposed Compressed Backup File (%s - %s)", task.path, matchedMagic.name)
			f.Severity = "critical"
			f.Description = fmt.Sprintf("A compressed backup archive '%s' was publicly accessible and verified via binary magic byte signature (%s).", task.path, matchedMagic.name)
			return archiveProbeResult{finding: f, signal: signal, promising: true}
		}
	}
	return archiveProbeResult{promising: promising}
}

func (r *Runner) lockBackupArchiveOrigin(origin string) func() {
	r.backupOriginMu.Lock()
	if r.backupOriginLocks == nil {
		r.backupOriginLocks = make(map[string]*sync.Mutex)
	}
	lock := r.backupOriginLocks[origin]
	if lock == nil {
		lock = &sync.Mutex{}
		r.backupOriginLocks[origin] = lock
	}
	r.backupOriginMu.Unlock()
	lock.Lock()
	return lock.Unlock
}

func (r *Runner) backupArchiveProbeDelay() time.Duration {
	live, ok := r.client.(interface{ IsLiveNetworkClient() bool })
	if !ok || !live.IsLiveNetworkClient() {
		return 0
	}
	if strings.EqualFold(r.cfg.ScanIntensity, "stealth") {
		return 2 * time.Second
	}
	return time.Second
}

func waitArchiveProbePace(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func archiveExtensionsForCandidate(name string) []string {
	lower := strings.ToLower(name)
	extensions := []string{"zip", "tar.gz", "7z", "rar", "tgz"}
	if strings.Contains(lower, "backup") || strings.Contains(lower, "archive") || strings.Contains(lower, "site") {
		extensions = append(extensions, "tar", "gz", "bz2", "xz")
	}
	if strings.Contains(lower, "db") || strings.Contains(lower, "sql") || strings.Contains(lower, "dump") || strings.Contains(lower, "database") || strings.Contains(lower, "data") {
		extensions = append(extensions, "sql.zip", "sql.gz", "sql.tar.gz", "db", "sqlite")
	}
	if strings.Contains(lower, ".") || strings.Contains(lower, "/") {
		extensions = append(extensions, "bak", "old")
	}
	if strings.Contains(lower, "release") || strings.Contains(lower, "webapp") || strings.Contains(lower, "package") {
		extensions = append(extensions, "war")
	}
	seen := make(map[string]struct{}, len(extensions))
	out := make([]string, 0, len(extensions))
	for _, ext := range extensions {
		if _, exists := seen[ext]; exists {
			continue
		}
		seen[ext] = struct{}{}
		out = append(out, ext)
	}
	return out
}

func archiveProbePriority(task archiveProbeTask) int {
	path := strings.ToLower(task.path)
	score := 100
	if path == "/backup.zip" {
		return 0
	}
	if strings.Contains(path, "backup") || strings.Contains(path, "archive") {
		score -= 50
	}
	if strings.Contains(path, "dump") || strings.Contains(path, "database") || strings.Contains(path, "/db.") {
		score -= 35
	}
	if task.ext == "zip" || task.ext == "tar.gz" {
		score -= 20
	}
	if strings.Count(path, "/") > 1 {
		score += 10
	}
	return score
}

func prioritizeArchiveProbeTasks(tasks []archiveProbeTask, preferredPaths []string) []archiveProbeTask {
	preferred := make(map[string]int, len(preferredPaths))
	for index, path := range preferredPaths {
		path = strings.ToLower(path)
		if _, exists := preferred[path]; !exists {
			preferred[path] = index
		}
	}
	sort.SliceStable(tasks, func(i, j int) bool {
		leftRank, leftPreferred := preferred[strings.ToLower(tasks[i].path)]
		rightRank, rightPreferred := preferred[strings.ToLower(tasks[j].path)]
		if leftPreferred != rightPreferred {
			return leftPreferred
		}
		if leftPreferred && leftRank != rightRank {
			return leftRank < rightRank
		}
		return archiveProbePriority(tasks[i]) < archiveProbePriority(tasks[j])
	})
	return tasks
}

func archivePathSuggestsBackup(path string) bool {
	lower := strings.ToLower(path)
	for _, marker := range []string{"backup", "backups", "archive", "dump", "export", "database"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func archiveLikeResponse(response httpclient.ResponseRecord) bool {
	contentType := strings.ToLower(headerCI(response.Headers, "Content-Type"))
	disposition := strings.ToLower(headerCI(response.Headers, "Content-Disposition"))
	for _, marker := range []string{"application/zip", "application/gzip", "application/x-7z", "application/x-rar", "application/x-tar", "application/octet-stream", "application/vnd.sqlite"} {
		if strings.Contains(contentType, marker) {
			return true
		}
	}
	return strings.Contains(disposition, "attachment")
}

func archiveBlockedResponse(response httpclient.ResponseRecord) bool {
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable ||
		(response.StatusCode >= 520 && response.StatusCode <= 527) {
		return true
	}
	lower := strings.ToLower(response.Body)
	for _, marker := range []string{
		"too many requests", "rate limit exceeded", "web application firewall", "request blocked",
		"checking your browser", "attention required", "cf-browser-verification", "incapsula_resource",
		"requested url was rejected", "your support id is", "captcha",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func bytesHasPrefix(s, prefix []byte) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := range prefix {
		if s[i] != prefix[i] {
			return false
		}
	}
	return true
}

func bytesContains(s, substr []byte) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := range substr {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func backupArchiveSignalConfirmed(signal string, response httpclient.ResponseRecord) bool {
	if (response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent) || !strings.HasPrefix(signal, "compressed_backup_disclosure_") {
		return false
	}
	bodyBytes := []byte(response.Body)
	if len(bodyBytes) < 4 {
		return false
	}
	for _, m := range archiveMagicSignatures {
		if len(m.magicBytes) == 0 || len(bodyBytes) < len(m.magicBytes) {
			continue
		}
		if bytesHasPrefix(bodyBytes, m.magicBytes) || bytesContains(bodyBytes[:minInt(len(bodyBytes), 512)], m.magicBytes) {
			return true
		}
	}
	return false
}
