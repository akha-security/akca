package modules

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/models"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestRuntimeWAFAutoDoesNotEnableHeadersOrOtherHosts(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/runtime.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err = db.EnsureScan("runtime-auto"); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveWAFProfile("runtime-auto", models.WAFProfile{Host: "waf.test:8443", Vendor: "Fastly"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	client := &wafHeaderCaptureClient{}
	r := NewRunner("runtime-auto", client, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), nil, nil, cfg)
	target := ScanTarget{EndpointURL: "https://waf.test:8443/search", Method: "GET", Parameter: "q", Location: "query"}
	if !r.wafHintsForTarget(target).AllowEvasion {
		t.Fatal("default runtime adaptation not enabled for detected WAF")
	}
	if sets := r.runtimeSQLiWAFVariantSets(target, []string{"' OR 1=1--", "' OR 1=2--"}); len(sets) == 0 || len(sets) > 2 {
		t.Fatalf("runtime variants=%d", len(sets))
	}
	if _, err = r.probeForModule(context.Background(), "sqli", target, "' OR 1=1--"); err != nil {
		t.Fatal(err)
	}
	for _, headers := range client.headers {
		if headers["X-Forwarded-For"] != "" || headers["Content-Type"] != "" {
			t.Fatalf("auto inserted WAF headers: %v", headers)
		}
	}
	for _, endpoint := range []string{"https://plain.test/search", "https://waf.test:9443/search"} {
		other := target
		other.EndpointURL = endpoint
		if r.wafHintsForTarget(other).AllowEvasion {
			t.Fatalf("WAF decision leaked to %s", endpoint)
		}
	}
	r.cfg.WAFPayloadMode = config.WAFPayloadOff
	if r.wafHintsForTarget(target).AllowEvasion || len(r.runtimeSQLiWAFVariantSets(target, []string{"' OR 1=1--"})) != 0 {
		t.Fatal("runtime ignored payload opt-out")
	}
}

func TestLoadedTargetsDropPersistedWAFVariantsWhenDisabled(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/resume.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err = db.EnsureScan("resume-waf"); err != nil {
		t.Fatal(err)
	}
	endpoint := "https://waf.test/search?q=1"
	id, err := db.EnsureEndpoint("resume-waf", endpoint, "GET")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.SaveParameter(id, "q", "query", 80); err != nil {
		t.Fatal(err)
	}
	generated := payloadgen.Generate(payloadgen.Input{Profile: reflection.ReflectionProfile{ScanID: "resume-waf", EndpointURL: endpoint, Method: "GET", Parameter: "q", ParameterLocation: "query", Context: reflection.ContextHTML, ReflectionKind: reflection.ReflectionRaw}, WAF: payloadgen.WAFHints{Vendor: "Cloudflare", AllowEvasion: true}, Budget: -1})
	if err = db.SaveGeneratedPayloadsContext(context.Background(), "resume-waf", endpoint, "q", generated); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.WAFPayloadMode = config.WAFPayloadOff
	r := NewRunner("resume-waf", &wafHeaderCaptureClient{}, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), nil, nil, cfg)
	targets, err := r.loadParameterTargets(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 || len(targets[0].Payloads.Payloads) == 0 {
		t.Fatal("stored originals were not loaded")
	}
	for _, target := range targets {
		for _, p := range target.Payloads.Payloads {
			if p.WAFAdapted {
				t.Fatal("stored WAF variant overrode opt-out")
			}
		}
	}
}
