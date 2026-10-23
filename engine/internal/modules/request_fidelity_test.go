package modules

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestNativeAndHeaderProbesKeepOriginalRequest(t *testing.T) {
	client := &recordingProbeClient{}
	r := NewRunner("scan", client, nil, nil, nil, nil, nil, config.DefaultScanConfig())
	target := ScanTarget{EndpointURL: "https://target.test/action?keep=1", Method: "PATCH", BodyTemplate: `{"action":"once"}`, RequestTemplate: reflection.RequestTemplate{Headers: map[string]string{"X-Tenant": "keep"}, ContentType: "application/json"}}
	if _, err := r.probe(context.Background(), target, "ignored"); err != nil {
		t.Fatal(err)
	}
	target.Parameter = "name"
	target.Location = "json"
	if _, err := r.probeWithHeaders(context.Background(), target, "", map[string]string{"Authorization": "Bearer user"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.probeHeadersOnlyForModule(context.Background(), "jwt", target, nil); err != nil {
		t.Fatal(err)
	}
	for _, call := range client.calls {
		if call.method != "PATCH" || call.rawURL != target.EndpointURL || string(call.body) != target.BodyTemplate || call.headers["X-Tenant"] != "keep" {
			t.Fatalf("request shape lost: %+v", call)
		}
	}
}

func TestFailedMutationDoesNotSendAnyRequest(t *testing.T) {
	client := &recordingProbeClient{}
	r := NewRunner("scan", client, nil, nil, nil, nil, nil, config.DefaultScanConfig())
	_, err := r.probe(context.Background(), ScanTarget{EndpointURL: "https://target.test/action", Method: "POST", Parameter: "user", Location: "json", BodyTemplate: `{"user":{},"csrf":"keep"}`}, "x")
	if err == nil || len(client.calls) != 0 || r.ProbeCount() != 0 {
		t.Fatalf("failed mutation sent a request: calls=%d err=%v", len(client.calls), err)
	}
}

func TestJWTProbesKeepNativeCarrierAndBody(t *testing.T) {
	for _, carrier := range []string{"cookie", "session-cookie", "query", "header"} {
		t.Run(carrier, func(t *testing.T) {
			client := &recordingProbeClient{}
			cfg := config.DefaultScanConfig()
			token := sampleValidJWT()
			target := ScanTarget{EndpointURL: "https://target.test/action?keep=1", Method: "POST", Parameter: "name", Location: "json", BodyTemplate: `{"name":"old","csrf":"keep"}`, RequestTemplate: reflection.RequestTemplate{Headers: map[string]string{"X-Tenant": "keep"}, ContentType: "application/json"}}
			switch carrier {
			case "cookie":
				target.RequestTemplate.Headers["cookie"] = "jwt=" + token + "; theme=dark"
			case "session-cookie":
				cfg.SessionCookies = map[string]string{"jwt": token}
			case "query":
				target.EndpointURL += "&jwt=not-a-token&jwt=" + url.QueryEscape(token)
			case "header":
				target.RequestTemplate.Headers["authorization"] = "Bearer " + token
			}
			r := NewRunner("scan", client, nil, nil, nil, nil, nil, cfg)
			if got := r.capturedJWTForTarget(target); got != token {
				t.Fatalf("capture=%q", got)
			}
			for _, replacement := range []string{token, invalidateJWTSignature(token)} {
				if _, err := r.probeJWT(context.Background(), target, replacement); err != nil {
					t.Fatal(err)
				}
				call := client.calls[len(client.calls)-1]
				if string(call.body) != target.BodyTemplate || call.method != "POST" || call.headers["X-Tenant"] != "keep" {
					t.Fatalf("shape lost: %+v", call)
				}
				headers := mergeHeaders(nil, call.headers)
				if carrier == "query" {
					u, _ := url.Parse(call.rawURL)
					if values := u.Query()["jwt"]; len(values) != 2 || values[0] != "not-a-token" || values[1] != replacement {
						t.Fatalf("query carrier: %s", call.rawURL)
					}
				} else if carrier == "header" {
					if headers["authorization"] != "Bearer "+replacement && headers["Authorization"] != "Bearer "+replacement {
						t.Fatalf("header carrier: %v", headers)
					}
				} else {
					raw := ""
					for k, v := range headers {
						if strings.EqualFold(k, "Cookie") {
							raw = v
						}
					}
					if !strings.Contains(raw, "jwt="+replacement) || strings.Contains(call.rawURL, "jwt=") {
						t.Fatalf("cookie carrier lost: %+v", call)
					}
				}
				if carrier != "header" {
					for k := range headers {
						if strings.EqualFold(k, "Authorization") {
							t.Fatal("JWT moved into Authorization")
						}
					}
				}
			}
		})
	}
}

func TestJWTClaimMutationPreservesLargeNumbers(t *testing.T) {
	token := buildJWT("HS256", `{"alg":"HS256"}`, `{"sub":"user","tenant_id":9007199254740993}`)
	tampered, ok := tamperJWTUnverifiedSignature(token, "other")
	if !ok {
		t.Fatal("tamper failed")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(tampered, ".")[1])
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil || string(doc["tenant_id"]) != "9007199254740993" {
		t.Fatalf("claim rounded: %s %v", raw, err)
	}
}

func TestPayloadWireEncodingReachesModuleRequest(t *testing.T) {
	client := &recordingProbeClient{}
	r := NewRunner("scan", client, nil, nil, nil, nil, nil, config.DefaultScanConfig())
	target := ScanTarget{EndpointURL: "https://target.test", Method: "POST", Parameter: "name", Location: "json", BodyTemplate: `{"name":"old","csrf":"keep"}`}
	p := payloadgen.Payload{Value: "<x>", VulnClass: "xss", Encoding: "json_unicode", WireEncoding: "json_unicode"}
	if _, err := r.probePayload(context.Background(), target, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(client.calls[0].body), `\u003c\u0078\u003e`) {
		t.Fatalf("wire encoding missing: %s", client.calls[0].body)
	}
}

func TestTestedEndpointCounterUsesDistinctCompletedIdentity(t *testing.T) {
	r := new(Runner)
	if r.TestedEndpointCount() != 0 {
		t.Fatal("count estimated without a completed target")
	}
	for _, target := range []ScanTarget{{EndpointURL: "https://target.test", Method: "GET", Parameter: "a"}, {EndpointURL: "https://target.test", Method: "GET", Parameter: "b"}, {EndpointURL: "https://target.test", Method: "POST"}} {
		r.markEndpointTested(target)
	}
	if got := r.TestedEndpointCount(); got != 2 {
		t.Fatalf("count=%d", got)
	}
}

func TestEndpointLoaderKeepsNativeRequestOnParameterlessTarget(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/native.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err = db.EnsureScan("scan"); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveDiscoveredEndpoint("scan", map[string]interface{}{"url": "https://target.test/action", "method": "POST", "request_template": map[string]interface{}{"body": `{"action":"once"}`, "content_type": "application/json", "headers": map[string]string{"X-Tenant": "keep"}}}); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	client := &recordingProbeClient{}
	r := NewRunner("scan", client, scope.NewEngine(cfg), db, nil, nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	targets, err := r.LoadTargetsWithEndpointsFromDB(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if target.Parameter != "" {
			continue
		}
		if _, err := r.probe(context.Background(), target, ""); err != nil {
			t.Fatal(err)
		}
		call := client.calls[len(client.calls)-1]
		if string(call.body) != `{"action":"once"}` || call.headers["X-Tenant"] != "keep" {
			t.Fatalf("loader dropped native shape: %+v", call)
		}
		return
	}
	t.Fatal("parameterless target missing")
}
