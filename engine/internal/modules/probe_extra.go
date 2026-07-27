package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) probeWithBody(ctx context.Context, target ScanTarget, body string, contentType string, headers map[string]string) (httpclient.RequestResponse, error) {
	return r.probeWithBodyForModule(ctx, "", target, body, contentType, headers)
}

func (r *Runner) probeWithBodyForModule(ctx context.Context, module string, target ScanTarget, body string, contentType string, headers map[string]string) (httpclient.RequestResponse, error) {
	method := strings.ToUpper(target.Method)
	if method == "" || method == "GET" {
		method = "POST"
	}
	if headers == nil {
		headers = map[string]string{}
	}
	if contentType != "" {
		headers["Content-Type"] = contentType
	}
	headers = mergeHeaders(headers, r.wafHeadersForModule(module, target.EndpointURL))
	bodyBytes := []byte(body)
	headers = sanitizeProbeHeaders(method, bodyBytes, headers)
	headers = r.registerRuntimeProbe(target, body, headers)
	return r.client.Do(ctx, method, target.EndpointURL, bodyBytes, headers)
}

func (r *Runner) cachedEmptyProbe(ctx context.Context, target ScanTarget) (httpclient.RequestResponse, error) {
	key := fmt.Sprintf("%s|%s|%s|%s|%s|%s", target.EndpointURL, strings.ToUpper(target.Method), target.Parameter, target.Location, target.Profile.ParameterLocation, target.Profile.ContentType)
	r.baselineMu.Lock()
	if rr, ok := r.baselineCache["probe|"+key]; ok {
		r.baselineMu.Unlock()
		return rr, nil
	}
	r.baselineMu.Unlock()

	rr, err := r.probe(ctx, target, "")
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	r.baselineMu.Lock()
	r.baselineCache["probe|"+key] = rr
	r.baselineMu.Unlock()
	return rr, nil
}

func (r *Runner) cachedEmptyHeaderProbe(ctx context.Context, target ScanTarget) (httpclient.RequestResponse, error) {
	key := fmt.Sprintf("%s|%s|%s|%s|%s|%s", target.EndpointURL, strings.ToUpper(target.Method), target.Parameter, target.Location, target.Profile.ParameterLocation, target.Profile.ContentType)
	r.baselineMu.Lock()
	if rr, ok := r.baselineCache["headers|"+key]; ok {
		r.baselineMu.Unlock()
		return rr, nil
	}
	r.baselineMu.Unlock()

	rr, err := r.probeWithHeaders(ctx, target, "", nil)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	r.baselineMu.Lock()
	r.baselineCache["headers|"+key] = rr
	r.baselineMu.Unlock()
	return rr, nil
}

func (r *Runner) probeWithHeaders(ctx context.Context, target ScanTarget, payload string, headers map[string]string) (httpclient.RequestResponse, error) {
	return r.probeWithHeadersForModule(ctx, "", target, payload, headers)
}

func (r *Runner) probeWithHeadersForModule(ctx context.Context, module string, target ScanTarget, payload string, headers map[string]string) (httpclient.RequestResponse, error) {
	if module != "" && len(headers) > 0 && !moduleAllowsHeaderPayloads(module) {
		headers = nil
	}
	method := strings.ToUpper(target.Method)
	if method == "" {
		method = "GET"
	}
	rawURL, err := injectParameter(target.EndpointURL, target.Parameter, payload)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	headers = mergeHeaders(headers, r.wafHeadersForModule(module, target.EndpointURL))
	headers = sanitizeProbeHeaders(method, nil, headers)
	headers = r.registerRuntimeProbe(target, payload, headers)
	return r.client.Do(ctx, method, rawURL, nil, headers)
}

func (r *Runner) recordFinding(out *[]ModuleFinding, f *ModuleFinding, module, signal string) {
	if f == nil || !findingProofEligible(*f) {
		return
	}
	_ = r.persistFinding(*f, module, signal)
	*out = append(*out, *f)
}

func findingProofEligible(f ModuleFinding) bool {
	if _, governed := verification.ProofPolicy(f.VulnClass); !governed {
		return true
	}
	result := f.Evidence.Verification
	return result.ProofSatisfied &&
		result.ProofPolicy == verification.CurrentProofPolicyVersion &&
		len(result.Observations) > 0 &&
		verification.ValidateObservations(result.Observations)
}

func defaultPayload(vulnClass, variant, value, signal string) payloadgen.Payload {
	return payloadgen.Payload{
		Value: value, VulnClass: vulnClass, Variant: variant, Family: vulnClass,
		ExpectedSignal: signal,
	}
}
