package modules

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func TestInstallerFingerprintRequiresIndependentSignals(t *testing.T) {
	positive := httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: `
		<html><title>Installation Wizard</title><p>System requirements</p>
		<form><label>Database host</label><button type="submit">Begin installation</button></form></html>`}
	if !installerFingerprintMatches(positive) {
		t.Fatal("expected real installer page to match")
	}
	negative := httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: `
		<html><article>This guide explains how to install application updates safely.</article></html>`}
	if installerFingerprintMatches(negative) {
		t.Fatal("documentation page must not match as an exposed installer")
	}
}
