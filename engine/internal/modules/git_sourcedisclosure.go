package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/gitrecover"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/sourcedisclosure"
)

func (r *Runner) runGitDeepRecovery(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("git_recovery", target); !ok {
		if ok2, _ := r.shouldRunModule("cicd_exposure", target); ok2 {
			return r.runCICDExposure(ctx, target)
		}
		r.emitSkip("git_recovery", target, reason)
		return nil
	}
	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}

	result := gitrecover.RecoveryResult{BaseURL: base}
	bodyByPath := map[string]string{}
	var proofExchange httpclient.RequestResponse

	for _, path := range gitrecover.PartialPaths {
		rawURL := base + path
		if !r.scope.IsInScope(rawURL) {
			continue
		}
		rr, err := r.client.Do(ctx, "GET", rawURL, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 || len(rr.Response.Body) < 2 {
			continue
		}
		result.FetchedPaths = append(result.FetchedPaths, path)
		bodyByPath[path] = rr.Response.Body
		if proofExchange.Request.URL == "" {
			proofExchange = rr
		}
	}

	if len(result.FetchedPaths) == 0 {
		return r.runCICDExposure(ctx, target)
	}

	if head, ok := bodyByPath["/.git/HEAD"]; ok && gitrecover.IsGitHEAD(head) {
		ref, hash := gitrecover.ParseHEAD(head)
		result.HEADRef = ref
		result.Branch = gitrecover.BranchFromRef(ref)
		if hash != "" {
			result.CommitHashes = append(result.CommitHashes, hash)
		}
	}
	for _, p := range []string{"/.git/logs/HEAD", "/.git/logs/refs/heads/master", "/.git/logs/refs/heads/main", "/.git/packed-refs"} {
		if body, ok := bodyByPath[p]; ok {
			result.CommitHashes = appendUniqueHashes(result.CommitHashes, gitrecover.ExtractCommitHashes(body)...)
		}
	}
	if cfg, ok := bodyByPath["/.git/config"]; ok && gitrecover.IsGitConfig(cfg) {
		urls, _ := gitrecover.ParseConfig(cfg)
		result.RemoteURLs = append(result.RemoteURLs, urls...)
	}
	if idxBody, ok := bodyByPath["/.git/index"]; ok {
		result.IndexPaths = gitrecover.ExtractIndexPaths([]byte(idxBody))
	}

	for _, hash := range result.CommitHashes {
		if len(result.ObjectPaths) >= 5 {
			break
		}
		if !gitrecover.ValidateObjectHash(hash) {
			continue
		}
		objPath := gitrecover.ObjectStoragePath(hash)
		objURL := base + objPath
		if !r.scope.IsInScope(objURL) {
			continue
		}
		rr, err := r.client.Do(ctx, "GET", objURL, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}
		result.ObjectPaths = append(result.ObjectPaths, objPath)
		decoded := gitrecover.DecodeLooseObject([]byte(rr.Response.Body))
		for _, f := range sourcedisclosure.Analyze(decoded) {
			_ = f
		}
	}

	var out []ModuleFinding
	severity := "high"
	if len(result.IndexPaths) > 0 || len(result.ObjectPaths) > 0 {
		severity = "critical"
	}
	desc := fmt.Sprintf(
		"Exposed .git artifacts at %s — fetched %d paths, branch=%q, commits=%d, index_files=%d, objects=%d, remotes=%d",
		base, len(result.FetchedPaths), result.Branch, len(result.CommitHashes),
		len(result.IndexPaths), len(result.ObjectPaths), len(result.RemoteURLs),
	)
	p := defaultPayload("git_recovery", "partial_git_exposure", strings.Join(result.FetchedPaths, ","), "partial_git_exposure")
	f := r.verifyAndBuild(ctx, "git_recovery", target, p, baseline, proofExchange,
		"partial_git_exposure", false, false, "", "")
	if f != nil {
		f.Title = "Exposed Git repository (" + result.Branch + ")"
		f.Severity = severity
		f.Description = desc
		r.recordFinding(ctx, &out, f, "git_recovery", "partial_git_exposure")
	}

	for _, ipath := range result.IndexPaths {
		if len(out) >= 3 {
			break
		}
		fileURL := base + "/" + strings.TrimPrefix(ipath, "/")
		if !r.scope.IsInScope(fileURL) {
			continue
		}
		rr, err := r.client.Do(ctx, "GET", fileURL, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}
		findings := r.sourceFindingsFromBody(ctx, target, baseline, fileURL, rr, "git_index_path")
		out = append(out, findings...)
	}
	return out
}

func appendUniqueHashes(existing []string, add ...string) []string {
	seen := map[string]struct{}{}
	for _, h := range existing {
		seen[h] = struct{}{}
	}
	for _, h := range add {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		existing = append(existing, h)
	}
	return existing
}

func (r *Runner) runSourceCodeDisclosure(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("source_code_disclosure", target); !ok {
		r.emitSkip("source_code_disclosure", target, reason)
		return nil
	}
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	var out []ModuleFinding

	candidates := sourcedisclosure.CandidateURLs(target.EndpointURL)
	for _, rawURL := range candidates {
		if !r.scope.IsInScope(rawURL) {
			continue
		}
		rr, err := r.client.Do(ctx, "GET", rawURL, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}
		ct := headerContentType(rr.Response.Headers)
		if !sourcedisclosure.LooksLikeSourceCode(rr.Response.Body, ct) && len(sourcedisclosure.Analyze(rr.Response.Body)) == 0 {
			continue
		}
		out = append(out, r.sourceFindingsFromBody(ctx, target, baseline, rawURL, rr, "source_disclosure")...)
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func (r *Runner) sourceFindingsFromBody(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse,
	rawURL string, rr httpclient.RequestResponse, module string) []ModuleFinding {
	findings := sourcedisclosure.Analyze(rr.Response.Body)
	if len(findings) == 0 && !sourcedisclosure.LooksLikeSourceCode(rr.Response.Body, headerContentType(rr.Response.Headers)) {
		return nil
	}
	var out []ModuleFinding
	if len(findings) == 0 {
		p := defaultPayload(module, "source_leak", rawURL, "source_code_disclosure")
		subTarget := target
		subTarget.EndpointURL = rawURL
		f := r.verifyAndBuild(ctx, module, subTarget, p, baseline, rr, "source_code_disclosure", false, false, "", "")
		if f != nil {
			f.Title = "Source code disclosure " + rawURL
			f.VulnClass = "source_code_disclosure"
			r.recordFinding(ctx, &out, f, "source_code_disclosure", "source_code_disclosure")
		}
		return out
	}
	for _, fd := range findings {
		p := defaultPayload("source_code_disclosure", fd.Kind, fd.Match, fd.Kind)
		subTarget := target
		subTarget.EndpointURL = rawURL
		f := r.verifyAndBuild(ctx, "source_code_disclosure", subTarget, p, baseline, rr, fd.Kind, false, false, "", "")
		if f == nil {
			continue
		}
		f.Title = "Source leak (" + fd.Kind + ") " + rawURL
		f.Severity = fd.Severity
		f.VulnClass = "source_code_disclosure"
		r.recordFinding(ctx, &out, f, "source_code_disclosure", fd.Kind)
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func headerContentType(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			return v
		}
	}
	return ""
}
