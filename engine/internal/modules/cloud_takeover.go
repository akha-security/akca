package modules

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type takeoverFingerprint struct {
	provider    string
	cnameSubstr string
	errorMsg    string
	severity    string
}

var takeoverFingerprints = []takeoverFingerprint{
	{provider: "AWS S3 Bucket", cnameSubstr: "s3.amazonaws.com", errorMsg: "NoSuchBucket", severity: "high"},
	{provider: "GitHub Pages", cnameSubstr: "github.io", errorMsg: "There isn't a GitHub Pages site here", severity: "high"},
	{provider: "Heroku", cnameSubstr: "herokudns.com", errorMsg: "No such app", severity: "high"},
	{provider: "Heroku", cnameSubstr: "herokuapp.com", errorMsg: "No such app", severity: "high"},
	{provider: "Shopify", cnameSubstr: "myshopify.com", errorMsg: "Sorry, this shop is currently unavailable", severity: "high"},
	{provider: "Azure App Service", cnameSubstr: "azurewebsites.net", errorMsg: "404 Web Site not found", severity: "high"},
	{provider: "Fastly", cnameSubstr: "fastly.net", errorMsg: "Fastly error: unknown domain", severity: "high"},
	{provider: "Pantheon", cnameSubstr: "pantheonsite.io", errorMsg: "404 error unknow site", severity: "high"},
	{provider: "WordPress.com", cnameSubstr: "wordpress.com", errorMsg: "Do you want to register", severity: "medium"},
	{provider: "Ghost", cnameSubstr: "ghost.io", errorMsg: "The blog you were looking for doesn't exist", severity: "high"},
	{provider: "Tumblr", cnameSubstr: "tumblr.com", errorMsg: "Whatever you were looking for doesn't get better than this", severity: "medium"},
	{provider: "Surge.sh", cnameSubstr: "surge.sh", errorMsg: "project not found", severity: "high"},
	{provider: "Vercel", cnameSubstr: "vercel-dns.com", errorMsg: "The deployment could not be found", severity: "high"},
	{provider: "Netlify", cnameSubstr: "netlify.app", errorMsg: "Not Found - Request ID", severity: "high"},
	{provider: "Fly.io", cnameSubstr: "edgeapp.net", errorMsg: "Could not find that app", severity: "high"},
	{provider: "Zendesk", cnameSubstr: "zendesk.com", errorMsg: "Help Center Closed", severity: "high"},
	{provider: "Bitbucket", cnameSubstr: "bitbucket.io", errorMsg: "Repository not found", severity: "high"},
	{provider: "Firebase", cnameSubstr: "firebaseapp.com", errorMsg: "Site Not Found", severity: "high"},
	{provider: "Webflow", cnameSubstr: "webflow.com", errorMsg: "The page you are looking for doesn't exist", severity: "high"},
	{provider: "Readme.io", cnameSubstr: "readme.io", errorMsg: "Project doesnt exist", severity: "high"},
	{provider: "Helpjuice", cnameSubstr: "helpjuice.com", errorMsg: "We could not find what you're looking for", severity: "high"},
	{provider: "Unbounce", cnameSubstr: "unbouncepages.com", errorMsg: "The requested URL was not found on this server. Please check the URL", severity: "high"},
	{provider: "Wix", cnameSubstr: "wixdns.net", errorMsg: "Looks Like This Domain Isn't Connected", severity: "high"},
	{provider: "Intercom", cnameSubstr: "custom.intercom.help", errorMsg: "This page is reserved for Intercom", severity: "high"},
	{provider: "Cargo Collective", cnameSubstr: "cargocollective.com", errorMsg: "404 &mdash; File not found", severity: "high"},
	{provider: "Strikingly", cnameSubstr: "s.strikinglydns.com", errorMsg: "PAGE NOT FOUND", severity: "high"},
	{provider: "Tictail", cnameSubstr: "domains.tictail.com", errorMsg: "to be used with", severity: "high"},
	{provider: "SmartJobBoard", cnameSubstr: "smartjobboard.com", errorMsg: "This job board currently does not exist", severity: "high"},
	{provider: "Landingi", cnameSubstr: "landingi.com", errorMsg: "It looks like you’re lost", severity: "high"},
}

func (r *Runner) runCloudTakeover(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cloud_takeover", target); !ok {
		r.emitSkip("cloud_takeover", target, reason)
		return nil
	}

	host := extractHost(target.EndpointURL)
	if host == "" {
		return nil
	}

	cname, err := net.DefaultResolver.LookupCNAME(ctx, host)
	if err != nil || cname == "" {
		return nil
	}
	cname = strings.TrimSuffix(strings.ToLower(cname), ".")

	var matchedFP *takeoverFingerprint
	for _, fp := range takeoverFingerprints {
		if strings.Contains(cname, fp.cnameSubstr) {
			matchedFP = &fp
			break
		}
	}

	if matchedFP == nil {
		return nil
	}

	// Fetch HTTP response to verify error fingerprint
	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		baseline = httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	}
	rr, err := r.probe(ctx, target, "")
	if err != nil {
		return nil
	}

	if !strings.Contains(rr.Response.Body, matchedFP.errorMsg) {
		return nil
	}

	// Double verification: both CNAME pointer and provider error message match
	signal := fmt.Sprintf("subdomain_takeover_%s", strings.ReplaceAll(strings.ToLower(matchedFP.provider), " ", "_"))
	p := defaultPayload("cloud_takeover", matchedFP.provider, cname, signal)
	f := r.verifyAndBuild(ctx, "cloud_takeover", target, p, baseline, rr, signal, false, false, "", "")

	var out []ModuleFinding
	if f != nil {
		f.Title = fmt.Sprintf("Dangling CNAME Subdomain Takeover (%s)", matchedFP.provider)
		f.Severity = matchedFP.severity
		f.Description = fmt.Sprintf("Subdomain '%s' has a CNAME record pointing to unclaimed %s resource (%s) and responded with the provider's unassigned error message.", host, matchedFP.provider, cname)
		r.recordFinding(ctx, &out, f, "cloud_takeover", signal)
	}

	return out
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	if idx := strings.Index(rawURL, "/"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	if idx := strings.Index(rawURL, ":"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

func cloudTakeoverSignalConfirmed(signal string, response httpclient.ResponseRecord) bool {
	if response.StatusCode <= 0 || !strings.HasPrefix(signal, "subdomain_takeover_") {
		return false
	}
	for _, fp := range takeoverFingerprints {
		expectedSignal := fmt.Sprintf("subdomain_takeover_%s", strings.ReplaceAll(strings.ToLower(fp.provider), " ", "_"))
		if signal == expectedSignal && strings.Contains(response.Body, fp.errorMsg) {
			return true
		}
	}
	return false
}
