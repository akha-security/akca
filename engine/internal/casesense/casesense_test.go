package casesense

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type mockClient struct {
	handler func(method, rawURL string) httpclient.ResponseRecord
}

func (m *mockClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	resp := m.handler(method, rawURL)
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: resp,
	}, nil
}

func TestFlipCase(t *testing.T) {
	if got := FlipCase("/Admin/Config"); got != "/aDMIN/cONFIG" {
		t.Errorf("FlipCase failed, got: %s", got)
	}
	if got := FlipCase("/123/456"); got != "/123/456" {
		t.Errorf("FlipCase with no alpha should remain unchanged, got: %s", got)
	}
}

func TestDetector(t *testing.T) {
	// 1. Case-insensitive server (Windows/IIS): returns 200 for both /admin and /ADMIN
	iisClient := &mockClient{
		handler: func(method, rawURL string) httpclient.ResponseRecord {
			return httpclient.ResponseRecord{StatusCode: 200, Body: "<h1>Admin Area</h1>"}
		},
	}
	d1 := NewDetector(iisClient)
	mode1, err := d1.Detect(context.Background(), "https://example.com/admin", 200, "<h1>Admin Area</h1>")
	if err != nil || mode1 != CaseInsensitive {
		t.Fatalf("expected CaseInsensitive, got %v (err: %v)", mode1, err)
	}

	// 2. Case-sensitive server (Linux/Nginx): returns 404 for /ADMIN
	nginxClient := &mockClient{
		handler: func(method, rawURL string) httpclient.ResponseRecord {
			if rawURL == "https://example.com/ADMIN" {
				return httpclient.ResponseRecord{StatusCode: 404, Body: "Not Found"}
			}
			return httpclient.ResponseRecord{StatusCode: 200, Body: "<h1>Admin Area</h1>"}
		},
	}
	d2 := NewDetector(nginxClient)
	mode2, err := d2.Detect(context.Background(), "https://example.com/admin", 200, "<h1>Admin Area</h1>")
	if err != nil || mode2 != CaseSensitive {
		t.Fatalf("expected CaseSensitive, got %v (err: %v)", mode2, err)
	}
}
