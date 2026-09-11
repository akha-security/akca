package modules

import (
	"bufio"
	"context"
	"fmt"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The controlled TCP fixture models a queued canary response. It verifies the
// real transport/verification path, not the vulnerability of a particular proxy.
func TestSmugglingKeepsRawReplayEvidence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var connections atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(conn)
				readRequest := func() string {
					var b strings.Builder
					n := 0
					for {
						line, e := reader.ReadString('\n')
						if e != nil {
							return ""
						}
						b.WriteString(line)
						if strings.HasPrefix(line, "Content-Length:") {
							n, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Content-Length:")))
						}
						if line == "\r\n" {
							break
						}
					}
					body := make([]byte, n)
					if _, e := io.ReadFull(reader, body); e != nil {
						return ""
					}
					b.Write(body)
					return b.String()
				}
				first := readRequest()

				if first == "" {
					return
				}
				fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nnormal")
				if readRequest() == "" {
					return
				}
				body := "normal"
				if token := regexp.MustCompile(`akca-smuggle-[a-zA-Z0-9_]+`).FindString(first); token != "" {
					body = token
				}
				fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			}()
		}
	}()
	rawURL := "http://" + listener.Addr().String() + "/"
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: "normal"}}, nil
	})
	r := newActiveRunner(t, c)
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{rawURL}
	r.scope = scope.NewEngine(cfg)
	findings := r.runHTTPSmuggling(context.Background(), ScanTarget{EndpointURL: rawURL, Method: "GET"})
	listener.Close()
	<-done
	if len(findings) != 1 {
		t.Fatalf("raw protocol proof suppressed: %d findings, connections=%d", len(findings), connections.Load())
	}
	f := findings[0]
	if f.Evidence.Verification.ProofType != verification.ProofProtocolDesync || connections.Load() != 3 {
		t.Fatalf("wrong protocol proof or connections: %s %d", f.Evidence.Verification.ProofType, connections.Load())
	}
	if !strings.Contains(f.Evidence.Request.Body, "Transfer-Encoding: chunked\r\n") || !strings.Contains(f.Evidence.Request.Body, "akca-smuggle-") {
		t.Fatal("raw wire evidence lost")
	}
}
