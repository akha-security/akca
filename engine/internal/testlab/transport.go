package testlab

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// LabTransport routes lab hostnames to a local httptest backend and counts requests.
type LabTransport struct {
	LabDomain  string
	BackendURL *url.URL
	Inner      http.RoundTripper
	count      atomic.Int64
}

func NewLabTransport(labDomain string, backend *url.URL) *LabTransport {
	return &LabTransport{
		LabDomain:  strings.ToLower(labDomain),
		BackendURL: backend,
		Inner:      http.DefaultTransport,
	}
}

func (t *LabTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.count.Add(1)
	cloned := req.Clone(req.Context())
	host := strings.ToLower(cloned.URL.Hostname())

	// Lab domain aliases are routed to the local httptest backend.
	if host == t.LabDomain || strings.HasSuffix(host, "."+t.LabDomain) {
		cloned.URL.Scheme = t.BackendURL.Scheme
		cloned.URL.Host = t.BackendURL.Host
		cloned.Host = t.BackendURL.Host
		return t.Inner.RoundTrip(cloned)
	}

	// Direct calls to the local backend (cfg targets include the raw URL) pass.
	if strings.EqualFold(cloned.URL.Host, t.BackendURL.Host) {
		return t.Inner.RoundTrip(cloned)
	}

	// Any other host is outside the lab. Never touch the real network: some
	// modules (cloud storage, smuggling, CVE probes, OAST)
	// derive external hosts, and real dials would hang on connection timeouts
	// and make the integration scan take many minutes. Synthesize an
	// unreachable response instead so the scan stays hermetic and fast.
	return &http.Response{
		StatusCode: http.StatusBadGateway,
		Status:     "502 Bad Gateway",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("lab: external host blocked")),
		Request:    req,
	}, nil
}

func (t *LabTransport) RequestCount() int64 {
	return t.count.Load()
}
