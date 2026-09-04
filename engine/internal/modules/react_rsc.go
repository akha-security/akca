package modules

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
)

type reactRSCProbe struct {
	name    string
	payload string
}

func (r *Runner) runReactRSCRCE(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("react_rsc_rce", target); !ok {
		r.emitSkip("react_rsc_rce", target, reason)
		return nil
	}
	probeURL, ok := reactRSCProbeURL(target.EndpointURL)
	if !ok {
		r.emitSkip("react_rsc_rce", target, "target URL is not parseable")
		return nil
	}
	probeTarget := target
	probeTarget.EndpointURL = probeURL
	probeTarget.Method = http.MethodPost
	probeTarget.Parameter = "rsc_body"
	probeTarget.Location = "body"

	baseline, err := r.cachedEmptyProbe(ctx, probeTarget)
	if err != nil {
		r.emitSkip("react_rsc_rce", target, "baseline failed: "+err.Error())
		return nil
	}
	benign, err := r.probeWithBodyForModule(ctx, "react_rsc_rce", probeTarget, `["$undefined"]`, "text/plain;charset=UTF-8", reactRSCHeaders())
	if err != nil {
		r.emitSkip("react_rsc_rce", target, "benign RSC control failed: "+err.Error())
		return nil
	}

	probes := []reactRSCProbe{
		{name: "rsc_flight_arg_decoder", payload: `["$1:a:a"]`},
		{name: "rsc_server_action_deserialization", payload: `["$K1","$K2","$1"]`},
		{name: "rsc_action_reference_probe", payload: `{"id":"akca_rsc_probe","bound":"$@1","args":["$1"]}`},
	}
	var findings []ModuleFinding
	for _, probe := range probes {
		payload := payloadgen.Payload{Value: probe.payload, VulnClass: "react_rsc_rce", Variant: probe.name}
		headers := r.registerRuntimeProbe(probeTarget, probe.payload, reactRSCHeaders())
		rr, err := r.client.Do(ctx, http.MethodPost, probeURL, []byte(probe.payload), headers)
		if err != nil {
			continue
		}
		if finding, handled := r.runtimeSinkProof(ctx, "react_rsc_rce", probeTarget, payload, baseline, rr); handled {
			if finding != nil {
				findings = append(findings, *finding)
			}
			continue
		}
		if reactRSCDecoderCrash(rr.Response) && !reactRSCDecoderCrash(benign.Response) {
			r.emitOnce("react-rsc-decoder-crash:"+probeURL, "module_notice",
				"React RSC decoder differential observed; runtime execution evidence is required before reporting RCE",
				map[string]interface{}{
					"url":     probeURL,
					"variant": probe.name,
					"status":  rr.Response.StatusCode,
				})
		}
	}
	return findings
}

func reactRSCProbeURL(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	u.Path = "/"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), true
}

func reactRSCHeaders() map[string]string {
	return map[string]string{
		"RSC":          "1",
		"Next-Action":  "akca_rsc_probe",
		"Accept":       "text/x-component",
		"Content-Type": "text/plain;charset=UTF-8",
	}
}

func reactRSCDecoderCrash(resp httpclient.ResponseRecord) bool {
	if resp.StatusCode != http.StatusInternalServerError {
		return false
	}
	body := strings.ToLower(resp.Body)
	contentType := strings.ToLower(resp.Headers["Content-Type"])
	return strings.Contains(contentType, "text/x-component") ||
		strings.Contains(body, "digest") ||
		strings.Contains(body, "server-side exception") ||
		strings.Contains(body, "deserialization") ||
		strings.Contains(body, "react server components")
}
