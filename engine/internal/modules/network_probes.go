package modules

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
)

type TLSInspection struct {
	Signals            []string
	Protocol           string
	Cipher             string
	CertificateSubject string
	CertificateIssuer  string
	CertificateExpiry  time.Time
}

type SmugglingProbeResult struct {
	Confirmed bool
	Signal    string
	Reason    string
	Exchange  httpclient.RequestResponse
	Control   httpclient.RequestResponse
	Attempts  []httpclient.RequestResponse
}

type networkTLSInspector struct {
	cfg config.ScanConfig
}

func newNetworkTLSInspector(cfg config.ScanConfig) TLSInspector {
	return &networkTLSInspector{cfg: cfg}
}

func (p *networkTLSInspector) Inspect(ctx context.Context, rawURL string) (TLSInspection, error) {
	u, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" {
		return TLSInspection{}, errors.New("TLS inspection requires an HTTPS target")
	}
	address := hostPort(u, "443")
	conn, err := p.dial(ctx, address, u.Hostname(), tls.VersionTLS12, 0, nil)
	if err != nil {
		return TLSInspection{}, err
	}
	state := conn.ConnectionState()
	_ = conn.Close()
	inspection := TLSInspection{Protocol: tlsVersionName(state.Version), Cipher: tls.CipherSuiteName(state.CipherSuite)}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		inspection.CertificateSubject = leaf.Subject.String()
		inspection.CertificateIssuer = leaf.Issuer.String()
		inspection.CertificateExpiry = leaf.NotAfter.UTC()
		now := time.Now()
		if now.Before(leaf.NotBefore) {
			inspection.Signals = append(inspection.Signals, "certificate_not_yet_valid")
		}
		if now.After(leaf.NotAfter) {
			inspection.Signals = append(inspection.Signals, "expired_certificate")
		} else if leaf.NotAfter.Sub(now) < 30*24*time.Hour {
			inspection.Signals = append(inspection.Signals, "certificate_expiring_soon")
		}
		if err := leaf.VerifyHostname(u.Hostname()); err != nil {
			inspection.Signals = append(inspection.Signals, "hostname_mismatch")
		}
		selfSigned := leaf.Subject.String() == leaf.Issuer.String() && leaf.CheckSignatureFrom(leaf) == nil
		if selfSigned {
			inspection.Signals = append(inspection.Signals, "self_signed_certificate")
		} else {
			intermediates := x509.NewCertPool()
			for _, certificate := range state.PeerCertificates[1:] {
				intermediates.AddCert(certificate)
			}
			if _, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: u.Hostname(), Intermediates: intermediates}); verifyErr != nil {
				inspection.Signals = append(inspection.Signals, "untrusted_certificate_chain")
			}
		}
	}
	if weakCipher(state.CipherSuite) {
		inspection.Signals = append(inspection.Signals, "weak_cipher")
	}
	for _, legacy := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		legacyConn, legacyErr := p.dial(ctx, address, u.Hostname(), legacy, legacy, nil)
		if legacyErr == nil {
			inspection.Signals = append(inspection.Signals, "weak_protocol")
			_ = legacyConn.Close()
			break
		}
	}
	weakSuites := []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}
	if weakConn, weakErr := p.dial(ctx, address, u.Hostname(), tls.VersionTLS10, tls.VersionTLS12, weakSuites); weakErr == nil {
		if weakCipher(weakConn.ConnectionState().CipherSuite) {
			inspection.Signals = append(inspection.Signals, "weak_cipher")
		}
		_ = weakConn.Close()
	}
	inspection.Signals = uniqueStrings(inspection.Signals)
	return inspection, nil
}

func (p *networkTLSInspector) dial(ctx context.Context, address, serverName string, minVersion, maxVersion uint16, suites []uint16) (*tls.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config: &tls.Config{
			ServerName: serverName, InsecureSkipVerify: true,
			MinVersion: minVersion, MaxVersion: maxVersion, CipherSuites: suites,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("TLS dial returned a non-TLS connection")
	}
	return tlsConn, nil
}

func weakCipher(id uint16) bool {
	switch id {
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return true
	default:
		return false
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

type networkWebSocketProber struct {
	cfg   config.ScanConfig
	scope *scope.Engine
}

func newNetworkWebSocketProber(cfg config.ScanConfig, scopeEngine *scope.Engine) WebSocketProber {
	return &networkWebSocketProber{cfg: cfg, scope: scopeEngine}
}

func (p *networkWebSocketProber) Probe(ctx context.Context, rawURL, payload string) (httpclient.RequestResponse, error) {
	u, err := websocketURL(rawURL)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	httpScopeURL := *u
	if u.Scheme == "wss" {
		httpScopeURL.Scheme = "https"
	} else {
		httpScopeURL.Scheme = "http"
	}
	if p.scope != nil && !p.scope.IsInScope(httpScopeURL.String()) {
		return httpclient.RequestResponse{}, fmt.Errorf("scope blocked websocket host: %s", u.Hostname())
	}
	conn, err := dialURL(ctx, u, p.cfg.InsecureSkipVerify)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	defer conn.Close()
	setConnDeadline(conn, ctx, 10*time.Second)

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return httpclient.RequestResponse{}, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	headers := map[string]string{
		"Host": u.Host, "Upgrade": "websocket", "Connection": "Upgrade",
		"Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13",
		"User-Agent": defaultProbeUserAgent,
	}
	for k, v := range p.cfg.CustomHeaders {
		headers[k] = v
	}
	if len(p.cfg.SessionCookies) > 0 {
		var cookies []string
		for k, v := range p.cfg.SessionCookies {
			cookies = append(cookies, k+"="+v)
		}
		headers["Cookie"] = strings.Join(cookies, "; ")
	}
	var request strings.Builder
	fmt.Fprintf(&request, "GET %s HTTP/1.1\r\n", path)
	for _, name := range []string{"Host", "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "User-Agent", "Cookie"} {
		if value := headers[name]; value != "" {
			fmt.Fprintf(&request, "%s: %s\r\n", name, value)
			delete(headers, name)
		}
	}
	for name, value := range headers {
		fmt.Fprintf(&request, "%s: %s\r\n", name, value)
	}
	request.WriteString("\r\n")
	if _, err := io.WriteString(conn, request.String()); err != nil {
		return httpclient.RequestResponse{}, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
		return httpclient.RequestResponse{}, fmt.Errorf("websocket upgrade rejected with status %d", response.StatusCode)
	}
	wantAccept := websocketAccept(key)
	if response.Header.Get("Sec-WebSocket-Accept") != wantAccept {
		return httpclient.RequestResponse{}, errors.New("invalid Sec-WebSocket-Accept")
	}
	if err := writeWebSocketText(conn, []byte(payload)); err != nil {
		return httpclient.RequestResponse{}, err
	}
	message, err := readWebSocketMessage(reader, conn)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: http.MethodGet, URL: u.String(), Headers: map[string]string{
			"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Version": "13",
		}, Body: payload},
		Response: httpclient.ResponseRecord{StatusCode: http.StatusSwitchingProtocols, Headers: headerMap(response.Header), Body: string(message)},
	}, nil
}

const defaultProbeUserAgent = "Akca-Security-Scanner/1.0"

func websocketURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("invalid websocket URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return nil, errors.New("unsupported websocket scheme")
	}
	return u, nil
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeWebSocketText(w io.Writer, payload []byte) error {
	frame := []byte{0x81}
	switch {
	case len(payload) < 126:
		frame = append(frame, 0x80|byte(len(payload)))
	case len(payload) <= 65535:
		frame = append(frame, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(frame[len(frame)-2:], uint16(len(payload)))
	default:
		frame = append(frame, 0x80|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(frame[len(frame)-8:], uint64(len(payload)))
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	_, err := w.Write(frame)
	return err
}

func readWebSocketMessage(r *bufio.Reader, w io.Writer) ([]byte, error) {
	var message []byte
	for frames := 0; frames < 8; frames++ {
		h, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		lengthByte, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		opcode := h & 0x0f
		masked := lengthByte&0x80 != 0
		length := uint64(lengthByte & 0x7f)
		if length == 126 {
			var b [2]byte
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return nil, err
			}
			length = uint64(binary.BigEndian.Uint16(b[:]))
		} else if length == 127 {
			var b [8]byte
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return nil, err
			}
			length = binary.BigEndian.Uint64(b[:])
		}
		if length > 2<<20 {
			return nil, errors.New("websocket frame exceeds 2 MiB")
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(r, mask[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch opcode {
		case 0x8:
			return nil, errors.New("websocket closed before a data response")
		case 0x9:
			if _, err := w.Write([]byte{0x8a, byte(len(payload))}); err == nil {
				_, _ = w.Write(payload)
			}
		case 0x0, 0x1, 0x2:
			message = append(message, payload...)
			if h&0x80 != 0 {
				return message, nil
			}
		}
	}
	return nil, errors.New("too many fragmented websocket frames")
}

type networkSmugglingProber struct {
	cfg   config.ScanConfig
	scope *scope.Engine
}

func newNetworkSmugglingProber(cfg config.ScanConfig, scopeEngine *scope.Engine) SmugglingProber {
	return &networkSmugglingProber{cfg: cfg, scope: scopeEngine}
}

func (p *networkSmugglingProber) Probe(ctx context.Context, rawURL, variant string) (SmugglingProbeResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return SmugglingProbeResult{}, errors.New("invalid smuggling target")
	}
	if p.scope != nil && !p.scope.IsInScope(rawURL) {
		return SmugglingProbeResult{}, errors.New("smuggling target is outside scope")
	}
	controlRaw := buildControlPipeline(u)
	control, err := p.exchange(ctx, u, controlRaw)
	if err != nil || len(control) < 2 {
		return SmugglingProbeResult{}, errors.New("target does not support a stable HTTP/1.1 keep-alive control")
	}
	controlExchange := httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: http.MethodPost, URL: rawURL, Body: controlRaw},
		Response: httpclient.ResponseRecord{
			StatusCode: control[0].StatusCode, Body: summarizeRawResponses(control),
		},
	}
	var confirmed int
	var confirmedAttempts []httpclient.RequestResponse
	var lastRaw string
	var lastResponses []rawHTTPResponse
	for attempt := 0; attempt < 2; attempt++ {
		token := randomToken(10)
		attackRaw, buildErr := buildSmugglingPipeline(u, strings.ToLower(variant), token)
		if buildErr != nil {
			return SmugglingProbeResult{}, buildErr
		}
		responses, exchangeErr := p.exchange(ctx, u, attackRaw)
		if exchangeErr != nil {
			continue
		}
		lastRaw, lastResponses = attackRaw, responses
		if desyncDifferential(control, responses) {
			confirmed++
			confirmedAttempts = append(confirmedAttempts, httpclient.RequestResponse{
				Request: httpclient.RequestRecord{Method: http.MethodPost, URL: rawURL, Body: attackRaw},
				Response: httpclient.ResponseRecord{
					StatusCode: responses[0].StatusCode, Body: summarizeRawResponses(responses),
				},
			})
		}
	}
	if confirmed < 2 {
		return SmugglingProbeResult{Confirmed: false, Signal: variant}, nil
	}
	return SmugglingProbeResult{
		Confirmed: true, Signal: variant,
		Reason: "repeated raw HTTP/1.1 response queue differential",
		Exchange: httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: http.MethodPost, URL: rawURL, Body: lastRaw},
			Response: httpclient.ResponseRecord{StatusCode: lastResponses[0].StatusCode, Body: summarizeRawResponses(lastResponses)},
		},
		Control: controlExchange, Attempts: confirmedAttempts,
	}, nil
}

type rawHTTPResponse struct {
	StatusCode int
	Body       string
}

func (p *networkSmugglingProber) exchange(ctx context.Context, u *url.URL, raw string) ([]rawHTTPResponse, error) {
	conn, err := dialURL(ctx, u, p.cfg.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	setConnDeadline(conn, ctx, 4*time.Second)
	if _, err := io.WriteString(conn, raw); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	var out []rawHTTPResponse
	for len(out) < 4 {
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			if len(out) > 0 && (errors.Is(err, io.EOF) || isNetTimeout(err)) {
				break
			}
			return out, err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 256<<10))
		_ = response.Body.Close()
		if readErr != nil {
			return out, readErr
		}
		out = append(out, rawHTTPResponse{StatusCode: response.StatusCode, Body: string(body)})
	}
	return out, nil
}

func buildControlPipeline(u *url.URL) string {
	path := requestPath(u)
	return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\nGET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, u.Host, path, u.Host)
}

func buildSmugglingPipeline(u *url.URL, variant, token string) (string, error) {
	path := requestPath(u)
	canaryPath := "/.well-known/akca-smuggling-" + token
	smuggled := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nX-Akca-Canary: %s\r\n\r\n", canaryPath, u.Host, token)
	body := "0\r\n\r\n" + smuggled
	contentLength := len(body)
	switch variant {
	case "cl_te":
		// A CL frontend consumes the full body while a TE backend stops at the
		// zero chunk, leaving the harmless GET canary queued.
	case "te_cl":
		// A TE frontend consumes the chunks while a CL backend consumes only
		// the zero-chunk prefix, leaving the same harmless GET canary queued.
		contentLength = len("0\r\n\r\n")
	default:
		return "", errors.New("unknown smuggling variant")
	}
	attack := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%s", path, u.Host, contentLength, body)
	victim := fmt.Sprintf("GET %s?akca_canary=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, token, u.Host)
	return attack + victim, nil
}

func desyncDifferential(control, probe []rawHTTPResponse) bool {
	if len(probe) > len(control) {
		return true
	}
	if len(probe) < 2 || len(control) < 2 {
		return false
	}
	return probe[1].StatusCode != control[1].StatusCode && probe[0].StatusCode == control[0].StatusCode
}

func summarizeRawResponses(responses []rawHTTPResponse) string {
	var parts []string
	for i, response := range responses {
		parts = append(parts, fmt.Sprintf("response[%d]=%d body=%q", i+1, response.StatusCode, truncateCloud(response.Body, 256)))
	}
	return strings.Join(parts, "\n")
}

func dialURL(ctx context.Context, u *url.URL, insecureSkipVerify bool) (net.Conn, error) {
	secure := strings.EqualFold(u.Scheme, "https") || strings.EqualFold(u.Scheme, "wss")
	defaultPort := "80"
	if secure {
		defaultPort = "443"
	}
	address := hostPort(u, defaultPort)
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	if !secure {
		return dialer.DialContext(ctx, "tcp", address)
	}
	tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{
		ServerName: u.Hostname(), InsecureSkipVerify: insecureSkipVerify, MinVersion: tls.VersionTLS12,
	}}
	return tlsDialer.DialContext(ctx, "tcp", address)
}

func hostPort(u *url.URL, defaultPort string) string {
	if u.Port() != "" {
		return net.JoinHostPort(u.Hostname(), u.Port())
	}
	return net.JoinHostPort(u.Hostname(), defaultPort)
}

func requestPath(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return path
}

func setConnDeadline(conn net.Conn, ctx context.Context, fallback time.Duration) {
	deadline := time.Now().Add(fallback)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
}

func headerMap(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for name, values := range headers {
		out[name] = strings.Join(values, ", ")
	}
	return out
}

func randomToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
