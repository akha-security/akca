package params

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/storage"
)

type integrityHTTPClient func(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error)

func (f integrityHTTPClient) Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	return f(ctx, method, rawURL, body, headers)
}

func integrityResponse(method, rawURL, body, contentType string, status int) httpclient.RequestResponse {
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: body, Headers: map[string]string{"Content-Type": contentType}},
	}
}

func TestNativeJSONMutationPreservesNumbersAndArrays(t *testing.T) {
	template := storage.DiscoveryRequestTemplate{ContentType: "application/json", Body: `{"large":9007199254740993,"items":[{"id":"old","keep":true},{"id":"second"}]}`}
	body, location, ok := mutateNativeBody(template, "items.0.id", "new")
	if !ok || location != LocationJSON || !strings.Contains(string(body), "9007199254740993") {
		t.Fatalf("number or mutation lost: %s (%v)", body, ok)
	}
	var document struct {
		Items []struct {
			ID   string `json:"id"`
			Keep bool   `json:"keep"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Items) != 2 || document.Items[0].ID != "new" || !document.Items[0].Keep || document.Items[1].ID != "second" {
		t.Fatalf("array/sibling damaged: %s", body)
	}
	for _, body := range []string{"null", `{"items":1}`, `{"items":[]} trailing`} {
		template.Body = body
		if result, _, ok := mutateNativeBody(template, "items.0.id", "new"); ok || result != nil {
			t.Fatalf("invalid mutation fell back to a different document: %s -> %s", body, result)
		}
	}
}

func multipartIntegrityTemplate(t *testing.T) storage.DiscoveryRequestTemplate {
	t.Helper()
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	if err := writer.SetBoundary("CaseSensitiveBoundary"); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("token", "keep"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("upload", "Report.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte{0, 1, 2, 255, '\r', '\n'}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return storage.DiscoveryRequestTemplate{ContentType: writer.FormDataContentType(), Body: buffer.String()}
}

func TestNativeMultipartMutationPreservesFileAndBoundary(t *testing.T) {
	template := multipartIntegrityTemplate(t)
	for _, name := range []string{"token", "debug"} {
		body, location, ok := mutateNativeBody(template, name, "changed")
		if !ok || location != LocationMultipart {
			t.Fatalf("multipart mutation failed: %v", ok)
		}
		_, parameters, err := mime.ParseMediaType(template.ContentType)
		if err != nil {
			t.Fatal(err)
		}
		reader := multipart.NewReader(bytes.NewReader(body), parameters["boundary"])
		fileFound, fieldFound := false, false
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(part)
			if err != nil {
				t.Fatal(err)
			}
			if part.FormName() == "upload" {
				fileFound = true
				if part.FileName() != "Report.bin" || !bytes.Equal(data, []byte{0, 1, 2, 255, '\r', '\n'}) {
					t.Fatalf("file changed: %q %v", part.FileName(), data)
				}
			}
			if part.FormName() == name && string(data) == "changed" {
				fieldFound = true
			}
		}
		if !fileFound || !fieldFound {
			t.Fatalf("file=%v field=%v", fileFound, fieldFound)
		}
	}
	template.Body = "truncated multipart body"
	if _, _, ok := mutateNativeBody(template, "debug", "x"); ok {
		t.Fatal("malformed multipart accepted")
	}
}

func TestTemplateExtractionUsesNativeSurfaces(t *testing.T) {
	for _, tc := range []struct {
		ct, body, name string
		location       Location
	}{
		{"application/xml", `<user kind="test"><name>alice</name><empty/></user>`, "user.name", LocationXML},
		{"application/xml", `<user kind="test"><name>alice</name></user>`, "user@kind", LocationXML},
		{"application/graphql", `query Test($id: ID = "one") { user(id: $id, name: "alice") { id } }`, "name", LocationGraphQLQuery},
		{"application/json", `{"items":[{"id":1}]}`, "items.0.id", LocationJSON},
	} {
		found := false
		for _, p := range ExtractFromTemplateBody("https://example.test/", "POST", tc.ct, tc.body) {
			if p.Location != tc.location {
				t.Fatalf("wrong surface: %+v", p)
			}
			if p.Name == tc.name {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s in %s", tc.name, tc.body)
		}
	}
	template := multipartIntegrityTemplate(t)
	parameters := ExtractFromTemplateBody("https://example.test/", "POST", template.ContentType, template.Body)
	if len(parameters) != 2 || parameters[0].Name != "token" || parameters[1].Name != "upload" {
		t.Fatalf("multipart fields: %+v", parameters)
	}
	for _, tc := range [][2]string{{"application/json", "not JSON"}, {"text/plain", "name=value"}, {"application/xml", "<broken>"}} {
		if parameters := ExtractFromTemplateBody("https://example.test/", "POST", tc[0], tc[1]); len(parameters) != 0 {
			t.Fatalf("misclassified body: %+v", parameters)
		}
	}
}

func TestNativeXMLAndGraphQLReplaceExistingValues(t *testing.T) {
	template := storage.DiscoveryRequestTemplate{ContentType: "application/xml", Body: `<root><id>one</id><other>keep</other></root>`}
	body, location, ok := mutateNativeBody(template, "root.id", "two")
	if !ok || location != LocationXML || strings.Count(string(body), "<id>") != 1 || !strings.Contains(string(body), "<id>two</id>") || !strings.Contains(string(body), "<other>keep</other>") {
		t.Fatalf("XML not replaced faithfully: %s", body)
	}
	if _, _, ok := mutateNativeBody(template, "unknown", "two"); ok {
		t.Fatal("unknown XML element appended")
	}
	template = storage.DiscoveryRequestTemplate{ContentType: "application/graphql", Body: `{ user(name: "alice", limit: 2) { id } }`}
	body, location, ok = mutateNativeBody(template, "name", "bob")
	if !ok || location != LocationGraphQLQuery || string(body) != `{ user(name: "bob", limit: 2) { id } }` {
		t.Fatalf("GraphQL shape changed: %s", body)
	}
}

func TestFailedReplayNeverConfirmsParameter(t *testing.T) {
	for _, surface := range []string{"query", "post_json", "native_json"} {
		t.Run(surface, func(t *testing.T) {
			rawURL := "https://example.test/search"
			d := newRunErrorDiscoverer(t, "failed-replay", []string{rawURL}, nil)
			d.SetWordlistCap(4)
			d.SetMaxProbes(40)
			var mu sync.Mutex
			attempts := map[string]int{}
			d.client = integrityHTTPClient(func(_ context.Context, method, target string, body []byte, _ map[string]string) (httpclient.RequestResponse, error) {
				ct, name := "text/plain", ""
				if surface == "post_json" {
					ct = "application/json"
				}
				if method == http.MethodGet && surface == "query" {
					u, _ := url.Parse(target)
					for key := range u.Query() {
						name = key
					}
				} else if method == http.MethodPost {
					var document map[string]interface{}
					_ = json.Unmarshal(body, &document)
					for key := range document {
						if key != "keep" {
							name = key
						}
					}
				}
				if name == "" || strings.HasPrefix(name, "__akca_rand_ctrl_") {
					return integrityResponse(method, target, "baseline", ct, 200), nil
				}
				mu.Lock()
				attempts[method+name]++
				n := attempts[method+name]
				mu.Unlock()
				if n > 1 {
					return httpclient.RequestResponse{}, errors.New("replay connection lost")
				}
				return integrityResponse(method, target, "accepted", ct, 202), nil
			})
			method := http.MethodGet
			template := storage.DiscoveryRequestTemplate{}
			if surface == "native_json" {
				method = http.MethodPost
				template.Body = `{"keep":"v"}`
				template.ContentType = "application/json"
			}
			id, err := d.db.EnsureEndpoint(d.scanID, rawURL, method)
			if err != nil {
				t.Fatal(err)
			}
			found, err := d.DiscoverEndpoint(context.Background(), id, rawURL, method, template)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range found {
				if p.Source == "differential" {
					t.Fatalf("failed replay confirmed: %+v", p)
				}
			}
			if len(attempts) == 0 {
				t.Fatal("no candidate replay tested")
			}
		})
	}
}

func TestFailedConcurrentProbesConsumeExactBudget(t *testing.T) {
	rawURL := "https://example.test/search"
	d := newRunErrorDiscoverer(t, "failed-budget", []string{rawURL}, nil)
	d.SetWordlistCap(40)
	d.SetMaxProbes(3)
	d.SetParallelism(10)
	var attempts atomic.Int64
	d.client = integrityHTTPClient(func(_ context.Context, method, target string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
		u, _ := url.Parse(target)
		if len(u.Query()) > 0 && !strings.Contains(target, "__akca_rand_ctrl_") {
			attempts.Add(1)
			return httpclient.RequestResponse{}, errors.New("candidate send failed")
		}
		return integrityResponse(method, target, "baseline", "text/plain", 200), nil
	})
	id, err := d.db.GetEndpointID(d.scanID, rawURL, "GET")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DiscoverEndpoint(context.Background(), id, rawURL, "GET"); err != nil {
		t.Fatal(err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts=%d, budget=3", got)
	}
}

func TestExhaustedBudgetCannotConfirmFirstSignal(t *testing.T) {
	rawURL := "https://example.test/search"
	d := newRunErrorDiscoverer(t, "replay-budget", []string{rawURL}, nil)
	d.SetMaxProbes(1)
	var attempts atomic.Int64
	d.client = integrityHTTPClient(func(_ context.Context, method, target string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
		u, _ := url.Parse(target)
		if len(u.Query()) > 0 && !strings.Contains(target, "__akca_rand_ctrl_") {
			attempts.Add(1)
			return integrityResponse(method, target, "accepted", "text/plain", 202), nil
		}
		return integrityResponse(method, target, "baseline", "text/plain", 200), nil
	})
	id, err := d.db.GetEndpointID(d.scanID, rawURL, "GET")
	if err != nil {
		t.Fatal(err)
	}
	found, err := d.DiscoverEndpoint(context.Background(), id, rawURL, "GET")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 || attempts.Load() != 1 {
		t.Fatalf("unreplayed result accepted or budget exceeded: %+v, attempts=%d", found, attempts.Load())
	}
}

func TestCapturedGETQueryIsPersistedBeforeSelection(t *testing.T) {
	d := newRunErrorDiscoverer(t, "captured-query", nil, nil)
	if err := d.db.SaveDiscoveredEndpoint(d.scanID, map[string]interface{}{
		"url": "https://example.test/article", "method": "GET", "source": "form",
		"request_template": map[string]interface{}{"url": "https://example.test/article?token=keep"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.Run(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := d.db.Conn().QueryRow(`SELECT COUNT(*) FROM parameters WHERE name = 'token' AND location = 'query'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("captured GET query lost: count=%d", count)
	}
}

func TestParameterFamiliesPreserveCaseAndEscapedPaths(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://example.test/API?id=1", "https://example.test/api?id=2"},
		{"https://example.test/api?ID=1", "https://example.test/api?id=2"},
		{"https://example.test/api/a%2Fb?id=1", "https://example.test/api/a/b?id=2"},
	} {
		a := parameterEndpointFamily(storage.DiscoveryEndpoint{URL: pair[0], Method: "GET"})
		b := parameterEndpointFamily(storage.DiscoveryEndpoint{URL: pair[1], Method: "GET"})
		if a == b {
			t.Fatalf("distinct families collapsed: %v", pair)
		}
	}
	a := storage.DiscoveryEndpoint{URL: "https://example.test/api", Method: "POST", RequestTemplate: storage.DiscoveryRequestTemplate{ContentType: "application/json", Body: `{"ID":1}`}}
	b := a
	b.RequestTemplate.Body = `{"id":1}`
	if parameterEndpointFamily(a) == parameterEndpointFamily(b) {
		t.Fatal("case-sensitive body names collapsed")
	}
	candidates := DifferentialCandidates(a.URL, nil, nil, map[string]struct{}{"ID": {}}, 1)
	if len(candidates) != 1 || candidates[0] != "id" {
		t.Fatalf("case-sensitive candidate skipped: %v", candidates)
	}
}

func TestPersistenceFailureIsReturnedEvenWithSuccessfulEndpoints(t *testing.T) {
	d := newRunErrorDiscoverer(t, "persistence", []string{"https://example.test/api/ok"}, nil)
	if err := d.db.SaveDiscoveredEndpoint(d.scanID, map[string]interface{}{
		"url": "https://example.test/api/save", "method": "POST", "source": "browser_xhr",
		"request_template": map[string]interface{}{"body": `{"keep":"v"}`, "content_type": "application/json"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Conn().Exec(`CREATE TRIGGER reject_parameters BEFORE INSERT ON parameters BEGIN SELECT RAISE(FAIL, 'parameter storage unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	d.client = integrityHTTPClient(func(_ context.Context, method, target string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
		status := 200
		if strings.Contains(target, "/ok") {
			status = 404
		}
		return integrityResponse(method, target, "baseline", "text/plain", status), nil
	})
	if err := d.Run(context.Background(), 10); !errors.Is(err, errParameterPersistence) {
		t.Fatalf("storage failure hidden: %v", err)
	}
}

func TestObservedQueryPersistenceFailureIsReturned(t *testing.T) {
	d := newRunErrorDiscoverer(t, "query-storage", []string{"https://example.test/api?id=1"}, nil)
	if _, err := d.db.Conn().Exec(`CREATE TRIGGER reject_parameters BEFORE INSERT ON parameters BEGIN SELECT RAISE(FAIL, 'parameter storage unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := d.Run(context.Background(), 10); !errors.Is(err, errParameterPersistence) {
		t.Fatalf("query storage failure hidden: %v", err)
	}
}
