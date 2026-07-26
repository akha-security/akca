package browserpool

import (
	"strings"
	"testing"
)

func TestHeadlessRendererPropagatesProxyAndTLSOptions(t *testing.T) {
	r := &HeadlessRenderer{
		proxyURL:    browserProxyURL("http://user:secret@127.0.0.1:8080"),
		insecureTLS: true,
	}
	args := strings.Join(r.commandArgs("https://example.com/"), " ")
	if !strings.Contains(args, "--proxy-server=http://127.0.0.1:8080") {
		t.Fatalf("browser proxy option missing: %s", args)
	}
	if strings.Contains(args, "secret") || strings.Contains(args, "user:") {
		t.Fatalf("proxy credentials leaked into browser process args: %s", args)
	}
	if !strings.Contains(args, "--ignore-certificate-errors") {
		t.Fatalf("browser TLS override missing: %s", args)
	}
}

func TestHeadlessRendererUsesIsolatedProfile(t *testing.T) {
	r := &HeadlessRenderer{}
	args := strings.Join(r.commandArgs("https://example.com/", `C:\temp\akca-profile`), " ")
	if !strings.Contains(args, `--user-data-dir=C:\temp\akca-profile`) {
		t.Fatalf("isolated browser profile option missing: %s", args)
	}
	if !strings.Contains(args, "--no-first-run") {
		t.Fatalf("first-run suppression missing: %s", args)
	}
}
