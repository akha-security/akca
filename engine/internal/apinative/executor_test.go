package apinative

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type dependencyReplayDoer struct {
	urls []string
}

func (d *dependencyReplayDoer) Do(_ context.Context, method, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
	d.urls = append(d.urls, rawURL)
	request := httpclient.RequestRecord{Method: method, URL: rawURL}
	switch rawURL {
	case "https://api.test/orders":
		return httpclient.RequestResponse{
			Request:  request,
			Response: httpclient.ResponseRecord{StatusCode: 200, Body: `{"orders":[{"id":"ord-7"}]}`},
		}, nil
	case "https://api.test/orders/ord-7":
		return httpclient.RequestResponse{
			Request:  request,
			Response: httpclient.ResponseRecord{StatusCode: 200, Body: `{"id":"ord-7","status":"paid"}`},
		}, nil
	default:
		return httpclient.RequestResponse{}, fmt.Errorf("unexpected URL %s", rawURL)
	}
}

func TestReplayReadOnlyBindsResponseIDIntoLaterPath(t *testing.T) {
	doer := &dependencyReplayDoer{}
	inventory := Inventory{Operations: []Operation{
		{ID: "listOrders", Method: http.MethodGet, URL: "https://api.test/orders"},
		{
			ID: "getOrder", Method: http.MethodGet, URL: "https://api.test/orders/{id}",
			Parameters: []Parameter{{Name: "id", In: "path", Type: "string"}},
		},
		{ID: "deleteOrder", Method: http.MethodDelete, URL: "https://api.test/orders/{id}"},
	}}
	summary := ReplayReadOnly(context.Background(), inventory, "https://api.test", doer)
	if summary.Attempted != 2 || summary.Succeeded != 2 || summary.SkippedUnsafe != 1 {
		t.Fatalf("unexpected replay summary: %+v", summary)
	}
	if len(doer.urls) != 2 || doer.urls[1] != "https://api.test/orders/ord-7" {
		t.Fatalf("response dependency was not bound: %+v", doer.urls)
	}
	if summary.DependenciesBound == 0 || summary.DependenciesFound == 0 {
		t.Fatalf("dependency metrics missing: %+v", summary)
	}
}
