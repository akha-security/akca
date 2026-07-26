package bypass403

import (
	"context"
	"net/url"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/fuzzing"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type authBypassDoer struct {
	baseline401 map[string]httpclient.ResponseRecord
}

func (d *authBypassDoer) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	key := method + " " + u.Path
	if auth, ok := headers["Authorization"]; ok && auth != "" {
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
			Response: httpclient.ResponseRecord{StatusCode: 200, Body: `{"admin":true}`},
		}, nil
	}
	if v, ok := headers["X-Original-URL"]; ok && v == "/api/secure" {
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
			Response: httpclient.ResponseRecord{StatusCode: 200, Body: `{"admin":true}`},
		}, nil
	}
	resp, ok := d.baseline401[key]
	if !ok {
		resp = httpclient.ResponseRecord{
			StatusCode: 401, Body: "Unauthorized",
			Headers: map[string]string{"WWW-Authenticate": `Bearer realm="api"`},
		}
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: resp,
	}, nil
}

func TestEngine401Bypass(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	newScope := scope.NewEngine(cfg)

	client := &authBypassDoer{baseline401: map[string]httpclient.ResponseRecord{
		"GET /api/secure": {
			StatusCode: 401, Body: "Unauthorized",
			Headers: map[string]string{"WWW-Authenticate": `Bearer realm="api"`},
		},
	}}

	db, err := storage.Open(t.TempDir() + "/bypass401.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()

	q := fuzzing.NewQueue403(10)
	q.Enqueue("http://127.0.0.1/api/secure", "GET")

	var succeeded int
	be := NewEngine("scan-401", client, newScope, db, q, func(eventType, _ string, _ map[string]interface{}) error {
		if eventType == "four_oh_one_bypass_succeeded" {
			succeeded++
		}
		return nil
	}, 1)

	if err := be.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if succeeded == 0 {
		t.Fatal("expected at least one 401 bypass success")
	}
}
