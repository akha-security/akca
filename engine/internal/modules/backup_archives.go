package modules

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
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
	finding *ModuleFinding
	signal  string
}

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

	// Archive Extensions
	extensions := []string{
		"zip", "tar.gz", "7z", "rar", "gz", "bz2", "xz", "tgz", "tar", "db", "sqlite",
		"sqlitedb", "sql.zip", "sql.gz", "sql.tar.gz", "sql.7z", "sql.rar", "war", "bak", "old",
	}

	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	runRootDictionary := r.moduleWorkOnce("backup_archives_root", baseURL)
	routePrefix := firstRoutePrefix(u.Path)
	baseline, baselineErr := r.cachedEmptyProbe(ctx, originTarget)
	if baselineErr != nil {
		return nil
	}
	seenPath := map[string]struct{}{}
	probeTasks := make([]archiveProbeTask, 0, len(rootCandidates)*len(extensions))
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
			for _, ext := range extensions {
				addProbe(fmt.Sprintf("/%s.%s", fname, ext), ext)
			}
		}
	}

	// 2. Route-derived candidates remain covered, but they stay under their
	// application prefix instead of multiplying the origin-wide root list.
	if routePrefix != "/" {
		for fname := range routeCandidates {
			for _, ext := range extensions {
				addProbe(fmt.Sprintf("%s/%s.%s", routePrefix, fname, ext), ext)
			}
		}
		for _, subPath := range directPathCandidates {
			for _, ext := range extensions {
				addProbe(fmt.Sprintf("%s.%s", subPath, ext), ext)
			}
		}
	}
	if len(probeTasks) == 0 {
		return nil
	}

	// Archive candidates are independent reads. Probe a bounded number in
	// parallel so a slow 404 path does not serialize the entire dictionary.
	// The HTTP client's global/per-host rate limits and the module allocation
	// still cap traffic; this changes wall-clock time, not coverage or volume.
	workers := r.cfg.PerHostConcurrency
	if workers <= 0 {
		workers = 8
	}
	workers = min(min(workers, 16), len(probeTasks))
	jobs := make(chan archiveProbeTask, workers)
	results := make(chan archiveProbeResult, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range jobs {
				if ctx.Err() != nil {
					return
				}
				if result := r.probeArchiveCandidate(ctx, originTarget, baseURL, task, baseline); result.finding != nil {
					results <- result
				}
			}
		}()
	}
	go func() {
		defer close(results)
		for _, task := range probeTasks {
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return
			case jobs <- task:
			}
		}
		close(jobs)
		wg.Wait()
	}()

	var out []ModuleFinding
	for result := range results {
		r.recordFinding(ctx, &out, result.finding, "backup_archives", result.signal)
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

	rr, err := r.probe(ctx, probeTarget, "")
	if err != nil || rr.Response.StatusCode != 200 {
		return archiveProbeResult{}
	}
	if rr.Response.Redirected && isRedirectedAway(rr, targetURL) {
		return archiveProbeResult{}
	}
	if isHTMLResponse(rr.Response) {
		return archiveProbeResult{}
	}

	// Strict Binary Magic Bytes Matching (Zero False Positive Proof Contract)
	bodyBytes := []byte(rr.Response.Body)
	if len(bodyBytes) < 4 {
		return archiveProbeResult{}
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
			return archiveProbeResult{finding: f, signal: signal}
		}
	}
	return archiveProbeResult{}
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
	if response.StatusCode != 200 || !strings.HasPrefix(signal, "compressed_backup_disclosure_") {
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
