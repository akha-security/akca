package browserpool

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-rod/rod/lib/launcher"
)

// HeadlessRenderer uses an installed Chromium-compatible browser. Dumping the
// post-execution DOM lets XSS verification observe mutations made by JavaScript.
type HeadlessRenderer struct {
	binary      string
	sem         chan struct{}
	proxyURL    string
	insecureTLS bool
	headers     map[string]string
	cookies     map[string]string
}

func NewHeadlessRenderer() *HeadlessRenderer {
	return NewHeadlessRendererWithProxy("", false)
}

func NewHeadlessRendererWithProxy(proxyURL string, insecureTLS bool) *HeadlessRenderer {
	if path := findBrowserBinary(); path != "" {
		return &HeadlessRenderer{
			binary: path, sem: make(chan struct{}, 2),
			proxyURL: browserProxyURL(proxyURL), insecureTLS: insecureTLS,
		}
	}
	return &HeadlessRenderer{proxyURL: browserProxyURL(proxyURL), insecureTLS: insecureTLS}
}

func findBrowserBinary() string {
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "msedge"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	for _, candidate := range windowsBrowserCandidates() {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	// Rod's browser manager has a stable per-user cache. Checking BinPath does
	// not access the network, but makes a previously auto-provisioned Chromium
	// visible to every renderer created later in the scan.
	downloaded := launcher.NewBrowser().BinPath()
	if info, err := os.Stat(downloaded); err == nil && !info.IsDir() {
		return downloaded
	}
	return ""
}

// EnsureBrowser returns a usable Chromium-compatible binary. Existing system
// browsers are preferred. If none exists, a portable Chromium build is
// downloaded once into the current user's browser cache.
func EnsureBrowser() (path string, downloaded bool, err error) {
	if path = findBrowserBinary(); path != "" {
		return path, false, nil
	}
	path, err = launcher.NewBrowser().Get()
	if err != nil {
		return "", false, fmt.Errorf("automatic Chromium provisioning failed: %w", err)
	}
	if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
		if statErr == nil {
			statErr = fmt.Errorf("downloaded path is a directory")
		}
		return "", false, fmt.Errorf("automatic Chromium provisioning produced an invalid binary: %w", statErr)
	}
	return path, true, nil
}

func (r *HeadlessRenderer) Available() bool { return r != nil && r.binary != "" }

func (r *HeadlessRenderer) SetSession(headers, cookies map[string]string) {
	r.headers = cloneStrings(headers)
	r.cookies = cloneStrings(cookies)
}

func (r *HeadlessRenderer) Render(ctx context.Context, rawURL string) (string, error) {
	if !r.Available() {
		return "", fmt.Errorf("no Chromium-compatible browser found")
	}
	// Authenticated rendering must use CDP so configured headers and cookies
	// are installed before navigation. Falling back to the CLI dump-DOM path
	// would silently render the anonymous page and could corrupt proof.
	if len(r.headers) > 0 || len(r.cookies) > 0 {
		snapshot, err := r.Capture(ctx, rawURL)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(snapshot.DOM) == "" {
			return "", fmt.Errorf("authenticated browser returned an empty DOM")
		}
		return snapshot.DOM, nil
	}
	if r.sem != nil {
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	profileDir, err := os.MkdirTemp("", "akca-browser-profile-*")
	if err != nil {
		return "", fmt.Errorf("create isolated browser profile: %w", err)
	}
	defer os.RemoveAll(profileDir)
	cmd := exec.CommandContext(ctx, r.binary, r.commandArgs(rawURL, profileDir)...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(out)) == "" {
		return "", fmt.Errorf("browser returned an empty DOM")
	}
	return string(out), nil
}

func cloneStrings(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func windowsBrowserCandidates() []string {
	var out []string
	roots := []string{os.Getenv("PROGRAMFILES"), os.Getenv("PROGRAMFILES(X86)"), os.Getenv("LOCALAPPDATA")}
	for _, parts := range [][]string{
		{"Microsoft", "Edge", "Application", "msedge.exe"},
		{"Google", "Chrome", "Application", "chrome.exe"},
	} {
		for _, root := range roots {
			if root == "" {
				continue
			}
			out = append(out, filepath.Join(append([]string{root}, parts...)...))
		}
	}
	return out
}

func (r *HeadlessRenderer) commandArgs(rawURL string, profileDirs ...string) []string {
	args := []string{
		"--headless=new", "--disable-gpu", "--disable-extensions",
		"--disable-background-networking", "--no-first-run", "--no-default-browser-check",
		"--virtual-time-budget=1500", "--dump-dom",
	}
	if len(profileDirs) > 0 && strings.TrimSpace(profileDirs[0]) != "" {
		args = append(args, "--user-data-dir="+profileDirs[0])
	}
	if r.proxyURL != "" {
		args = append(args, "--proxy-server="+r.proxyURL)
	}
	if r.insecureTLS {
		args = append(args, "--ignore-certificate-errors")
	}
	return append(args, rawURL)
}

func browserProxyURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	// Chromium's --proxy-server switch does not accept URL userinfo. Core HTTP
	// traffic still supports authenticated proxies; browser rendering falls back
	// to the credential-free endpoint without exposing secrets in process args.
	u.User = nil
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return u.String()
}
