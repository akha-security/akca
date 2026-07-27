package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
)

func (r *Runner) RunGroupB(ctx context.Context, targets []ScanTarget) ([]ModuleFinding, error) {
	_ = r.emit("vuln_modules_b_started", "SSRF, LFI & XXE scanning started", map[string]interface{}{
		"scan_id": r.scanID, "targets": len(targets),
	})

	workers := r.cfg.PerHostConcurrency
	if workers <= 0 {
		workers = 8
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	var mu sync.Mutex
	var findings []ModuleFinding

	targetCh := make(chan ScanTarget, len(targets))
	for _, t := range targets {
		targetCh <- t
	}
	close(targetCh)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetCh {
				if ctx.Err() != nil {
					return
				}
				if !r.scope.IsInScope(target.EndpointURL) {
					continue
				}
				var localFindings []ModuleFinding
				if r.cfg.AllowsModule("ssrf") {
					localFindings = append(localFindings, r.runSSRF(ctx, target)...)
				}
				if r.cfg.AllowsModule("xxe") {
					localFindings = append(localFindings, r.runXXE(ctx, target)...)
				}
				if r.cfg.AllowsModule("lfi") {
					localFindings = append(localFindings, r.runLFI(ctx, target)...)
				}
				if r.cfg.AllowsModule("file_upload") {
					localFindings = append(localFindings, r.runFileUpload(ctx, target)...)
				}
				if r.cfg.AllowsModule("idor") {
					localFindings = append(localFindings, r.runIDOR(ctx, target)...)
				}
				if r.cfg.AllowsModule("bfla") {
					localFindings = append(localFindings, r.runBFLA(ctx, target)...)
				}
				if r.cfg.AllowsModule("open_redirect") {
					localFindings = append(localFindings, r.runOpenRedirect(ctx, target)...)
				}
				if r.cfg.AllowsModule("host_header") {
					localFindings = append(localFindings, r.runHostHeader(ctx, target)...)
				}
				if r.cfg.AllowsModule("second_order") {
					localFindings = append(localFindings, r.runSecondOrder(ctx, target)...)
				}

				if len(localFindings) > 0 {
					mu.Lock()
					findings = append(findings, localFindings...)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	_ = r.emit("vuln_modules_b_finished", "SSRF, LFI & XXE scanning finished", map[string]interface{}{
		"scan_id": r.scanID, "findings": len(findings),
	})
	return findings, nil
}

func (r *Runner) RunGroupBFromDB(ctx context.Context, limit int) ([]ModuleFinding, error) {
	targets, err := r.LoadTargetsWithEndpointsFromDB(limit)
	if err != nil {
		return nil, err
	}
	return r.RunGroupB(ctx, targets)
}

func (r *Runner) runSSRF(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("ssrf", target); !ok {
		r.emitSkip("ssrf", target, reason)
		return nil
	}
	strongCandidate, _ := ssrfReady(target)
	oastURL := ""
	if r.cfg.EnableOAST && r.oast != nil {
		oastURL = strings.TrimSpace(r.oastURL(ctx, "ssrf-"+target.Parameter, target, "ssrf"))
	}
	_ = r.emit("ssrf_probe_started", "SSRF probe coverage started", map[string]interface{}{
		"scan_id": r.scanID, "endpoint": target.EndpointURL, "parameter": target.Parameter,
		"mode": map[bool]string{true: "direct_and_oast", false: "oast_only"}[strongCandidate],
	})
	if !strongCandidate {
		if oastURL == "" {
			r.emitSkip("ssrf", target, "weak SSRF candidate requires OAST, but no callback URL is available")
			return nil
		}
		for _, p := range r.modulePayloads(target, "ssrf", oastURL) {
			if p.ExpectedSignal == "blind_oast" {
				r.sendOASTProbe(ctx, target, strings.TrimSpace(p.Value))
			}
		}
		return nil
	}
	baseline, ok := r.stableNativeBaselineForModule(ctx, "ssrf", target)
	if !ok {
		return nil
	}
	type directObservation struct {
		payload payloadgen.Payload
		rr      httpclient.RequestResponse
	}
	observations := map[string][]directObservation{}
	var out []ModuleFinding
	for _, p := range r.modulePayloads(target, "ssrf", oastURL) {
		if p.ExpectedSignal == "blind_oast" {
			if oastURL == "" {
				continue
			}
			r.sendOASTProbe(ctx, target, strings.TrimSpace(p.Value))
			continue
		}
		rr, err := r.probeSSRF(ctx, target, p)
		if err != nil {
			continue
		}
		if runtimeFinding, handled := r.runtimeSinkProof(ctx, "ssrf", target, p, baseline, rr); handled {
			if runtimeFinding != nil {
				r.recordFinding(&out, runtimeFinding, "ssrf", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		signal := normalizedSSRFSignal(p)
		if !ssrfSignalConfirmed(p, baseline.Response, rr.Response, signal) {
			continue
		}
		observations[signal] = append(observations[signal], directObservation{payload: p, rr: rr})
	}

	for signal, proofs := range observations {
		if len(proofs) < 2 {
			continue
		}
		first := proofs[0]
		f := r.verifyAndBuild(ctx, "ssrf", target, first.payload, baseline, first.rr, signal, false, false, "", "")
		if f != nil {
			f.Description += " Confirmed by two independent provider-specific direct-response probes."
			f.Evidence.Verification.UpgradeReasons = append(f.Evidence.Verification.UpgradeReasons,
				"two_provider_specific_probes")
		}
		r.recordFinding(&out, f, "ssrf", signal)
	}
	return out
}

func ssrfSignal(body, baseline, signal string) bool {
	p := payloadgen.Payload{ExpectedSignal: signal}
	return ssrfSignalConfirmed(p,
		httpclient.ResponseRecord{Body: baseline},
		httpclient.ResponseRecord{Body: body},
		signal,
	)
}

func normalizedSSRFSignal(p payloadgen.Payload) string {
	signal := strings.TrimSpace(p.ExpectedSignal)
	if signal != "" && signal != "cloud_metadata" {
		return signal
	}
	value := strings.ToLower(p.Value)
	switch {
	case strings.Contains(value, "metadata.google"):
		return "gcp_metadata"
	case strings.Contains(value, "metadata/instance"):
		return "azure_metadata"
	default:
		return "aws_metadata"
	}
}

func (r *Runner) probeSSRF(ctx context.Context, target ScanTarget, p payloadgen.Payload) (httpclient.RequestResponse, error) {
	headers := map[string]string{}
	switch normalizedSSRFSignal(p) {
	case "gcp_metadata":
		headers["Metadata-Flavor"] = "Google"
	case "azure_metadata":
		headers["Metadata"] = "true"
	}
	if len(headers) > 0 {
		return r.probeWithHeadersForModule(ctx, "ssrf", target, strings.TrimSpace(p.Value), headers)
	}
	return r.probeForModule(ctx, "ssrf", target, strings.TrimSpace(p.Value))
}

func (r *Runner) stableNativeBaseline(ctx context.Context, target ScanTarget) (httpclient.RequestResponse, bool) {
	return r.stableNativeBaselineForModule(ctx, "", target)
}

func (r *Runner) stableNativeBaselineForModule(ctx context.Context, module string, target ScanTarget) (httpclient.RequestResponse, bool) {
	value := nativeTargetValue(target)
	var first httpclient.RequestResponse
	for i := 0; i < 3; i++ {
		rr, err := r.probeForModule(ctx, module, target, value)
		if err != nil {
			return httpclient.RequestResponse{}, false
		}
		if i == 0 {
			first = rr
			continue
		}
		if rr.Response.StatusCode != first.Response.StatusCode ||
			bodyDiffRatio(normalizeVolatileFields(first.Response.Body), normalizeVolatileFields(rr.Response.Body)) > 0.05 {
			return httpclient.RequestResponse{}, false
		}
	}
	return first, true
}

func nativeTargetValue(target ScanTarget) string {
	u, err := url.Parse(target.EndpointURL)
	if err == nil && target.Parameter != "" {
		if value, exists := u.Query()[target.Parameter]; exists && len(value) > 0 {
			return value[0]
		}
	}
	if target.BodyTemplate != "" && target.Parameter != "" {
		location := strings.ToLower(strings.TrimSpace(target.Location))
		if location == "form" {
			if values, err := url.ParseQuery(target.BodyTemplate); err == nil {
				return values.Get(target.Parameter)
			}
		}
		if location == "json" || strings.Contains(strings.ToLower(target.Profile.ContentType), "json") {
			var object map[string]any
			if json.Unmarshal([]byte(target.BodyTemplate), &object) == nil {
				if value, exists := object[target.Parameter]; exists {
					return fmt.Sprint(value)
				}
			}
		}
	}
	return ""
}
