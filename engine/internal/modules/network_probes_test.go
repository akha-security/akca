package modules

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/scope"
)

func TestNetworkTLSInspectorReadsRealHandshake(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	inspection, err := newNetworkTLSInspector(config.DefaultScanConfig()).Inspect(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Protocol == "" || inspection.Cipher == "" || inspection.CertificateSubject == "" {
		t.Fatalf("incomplete real TLS inspection: %+v", inspection)
	}
	if !containsString(inspection.Signals, "self_signed_certificate") {
		t.Fatalf("httptest certificate should be recognized as self-signed: %+v", inspection.Signals)
	}
}

func TestNetworkWebSocketProberPerformsHandshakeAndFrameExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("server does not support hijacking")
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		accept := websocketAccept(request.Header.Get("Sec-WebSocket-Key"))
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
		_ = rw.Flush()
		payload, err := readMaskedClientFrame(rw.Reader)
		if err != nil {
			t.Error(err)
			return
		}
		response := []byte("echo:" + string(payload))
		frame := []byte{0x81, byte(len(response))}
		frame = append(frame, response...)
		_, _ = conn.Write(frame)
	}))
	defer server.Close()

	cfg := config.DefaultScanConfig()
	prober := newNetworkWebSocketProber(cfg, scope.NewEngine(cfg))
	rr, err := prober.Probe(context.Background(), server.URL+"/socket", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if rr.Response.StatusCode != http.StatusSwitchingProtocols || rr.Response.Body != "echo:hello" {
		t.Fatalf("unexpected websocket exchange: %+v", rr)
	}
}

func TestSmugglingPipelineUsesRawConflictingFramingAndHarmlessCanary(t *testing.T) {
	u, _ := url.Parse("https://example.com/orders")
	for _, variant := range []string{
		"cl_te", "te_cl", "te_te_space", "te_te_prefix", "te_te_duplicate", "cl_cl_conflict",
		"cl_te_crlf", "te_cl_tab", "te_newline",
	} {
		raw, err := buildSmugglingPipeline(u, variant, "token")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(raw, "Content-Length:") {
			t.Fatalf("%s does not contain framing:\n%s", variant, raw)
		}
		if !strings.Contains(raw, "GET /.well-known/akca-smuggling-token") {
			t.Fatalf("%s is missing the harmless canary request", variant)
		}
		if strings.Contains(strings.ToLower(raw), "/admin") {
			t.Fatalf("%s must not target an application resource such as /admin", variant)
		}
	}
}

func TestCloudStorageCandidatesAreDiscoveredNotGuessed(t *testing.T) {
	body := `<script>window.bucket="https://assets.s3.amazonaws.com/public/"</script>`
	candidates := cloudStorageCandidates("https://example.com/", body)
	if len(candidates) != 1 || candidates[0] != "https://assets.s3.amazonaws.com/public/" {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
	if guessed := cloudStorageCandidates("https://example.com/", ""); len(guessed) != 0 {
		t.Fatalf("ordinary target hostname must not be converted into guessed buckets: %#v", guessed)
	}
}

func readMaskedClientFrame(reader *bufio.Reader) ([]byte, error) {
	if _, err := reader.ReadByte(); err != nil {
		return nil, err
	}
	lengthByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	length := uint64(lengthByte & 0x7f)
	if length == 126 {
		var raw [2]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(raw[:]))
	}
	var mask [4]byte
	if _, err := io.ReadFull(reader, mask[:]); err != nil {
		return nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return payload, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
