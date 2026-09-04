package modules

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
)

func TestH2SmugglingProberRejectsNonHTTPS(t *testing.T) {
	prober := NewH2SmugglingProber(config.DefaultScanConfig())
	res, err := prober.ProbeH2Desync(context.Background(), "http://example.com/test", "h2_cl")
	if err == nil {
		t.Fatal("expected error for non-HTTPS target in H2 desync prober")
	}
	if res.Confirmed {
		t.Fatal("probe should not be confirmed on non-HTTPS target")
	}
}

func TestH2CUpgradeProbe(t *testing.T) {
	// Mock server that returns a regular 200 OK (not 101 Switching Protocols)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ordinary response"))
	}))
	defer server.Close()

	prober := NewH2SmugglingProber(config.DefaultScanConfig())
	res, err := prober.ProbeH2CUpgrade(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Confirmed {
		t.Fatal("h2c upgrade should not be confirmed on standard HTTP/1.1 endpoint")
	}
}

func TestH2CUpgradeConfirmed(t *testing.T) {
	// Mock server simulating a reverse proxy that accepts h2c upgrade with 101 Switching Protocols
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				req := string(buf[:n])
				if req != "" {
					response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
					_, _ = c.Write([]byte(response))
				}
			}(conn)
		}
	}()

	prober := NewH2SmugglingProber(config.DefaultScanConfig())
	res, err := prober.ProbeH2CUpgrade(context.Background(), "http://"+listener.Addr().String()+"/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Confirmed {
		t.Fatal("expected h2c upgrade to be confirmed on 101 Switching Protocols server")
	}
	if res.Signal != "h2c_upgrade_confusion" {
		t.Fatalf("unexpected signal: %s", res.Signal)
	}
}
