package subdomain

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/branding"
)

// DiscoveredDomain represents a discovered target domain.
type DiscoveredDomain struct {
	Hostname string   `json:"hostname"`
	LiveURLs []string `json:"live_urls"`
	Source   string   `json:"source"`
}

// Engine performs passive subdomain discovery and live probing without external tools.
type Engine struct {
	client *http.Client
}

// New creates a new native Subdomain Engine.
func New() *Engine {
	return &Engine{
		client: &http.Client{
			Timeout: 12 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout: 5 * time.Second,
				}).DialContext,
			},
		},
	}
}

// DiscoverAndProbe finds passive subdomains for rootDomain and probes live HTTP/HTTPS ports.
func (e *Engine) DiscoverAndProbe(ctx context.Context, rootDomain string) ([]DiscoveredDomain, []string, error) {
	rootDomain = sanitizeDomain(rootDomain)
	if rootDomain == "" {
		return nil, nil, fmt.Errorf("invalid root domain")
	}

	wildcardIP := detectWildcardIP(ctx, rootDomain)

	subdomains := e.fetchPassiveSubdomains(ctx, rootDomain)
	if len(subdomains) == 0 {
		subdomains = []string{rootDomain, "www." + rootDomain}
	}

	liveDomains, allLiveURLs := e.probeLiveSubdomains(ctx, subdomains, wildcardIP)
	return liveDomains, allLiveURLs, nil
}

func sanitizeDomain(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	if idx := strings.Index(raw, ":"); idx != -1 {
		raw = raw[:idx]
	}
	return strings.TrimPrefix(raw, "www.")
}

func (e *Engine) fetchPassiveSubdomains(ctx context.Context, rootDomain string) []string {
	var mu sync.Mutex
	found := make(map[string]struct{})
	found[rootDomain] = struct{}{}
	found["www."+rootDomain] = struct{}{}

	add := func(domain string) {
		domain = strings.TrimSpace(strings.ToLower(domain))
		domain = strings.TrimPrefix(domain, "*.")
		domain = strings.TrimPrefix(domain, ".")
		if !belongsToRootDomain(domain, rootDomain) {
			return
		}
		if isValidHostname(domain) {
			mu.Lock()
			found[domain] = struct{}{}
			mu.Unlock()
		}
	}

	var wg sync.WaitGroup

	// 1. CRT.sh (Certificate Transparency)
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.queryCRTsh(ctx, rootDomain, add)
	}()

	// 2. AlienVault OTX
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.queryAlienVault(ctx, rootDomain, add)
	}()

	// 3. HackerTarget
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.queryHackerTarget(ctx, rootDomain, add)
	}()

	// 4. JLDC Anonym
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.queryJLDC(ctx, rootDomain, add)
	}()

	// 5. Archive.org / Wayback Machine (Historical Mining)
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.queryWaybackMachine(ctx, rootDomain, add)
	}()

	// 6. CertSpotter API
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.queryCertSpotter(ctx, rootDomain, add)
	}()

	// 7. ThreatMiner API
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.queryThreatMiner(ctx, rootDomain, add)
	}()

	// 8. SubdomainCenter API
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.querySubdomainCenter(ctx, rootDomain, add)
	}()

	wg.Wait()

	out := make([]string, 0, len(found))
	for d := range found {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func belongsToRootDomain(domain, rootDomain string) bool {
	return domain == rootDomain || strings.HasSuffix(domain, "."+rootDomain)
}

func (e *Engine) queryCRTsh(ctx context.Context, domain string, add func(string)) {
	reqURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", branding.UserAgent)

	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return
	}

	var records []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &records); err != nil {
		return
	}

	for _, r := range records {
		for _, name := range strings.Split(r.NameValue, "\n") {
			add(name)
		}
	}
}

func (e *Engine) queryAlienVault(ctx context.Context, domain string, add func(string)) {
	reqURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", branding.UserAgent)

	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return
	}

	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return
	}

	for _, entry := range data.PassiveDNS {
		add(entry.Hostname)
	}
}

func (e *Engine) queryHackerTarget(ctx context.Context, domain string, add func(string)) {
	reqURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", branding.UserAgent)

	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			add(parts[0])
		}
	}
}

func (e *Engine) queryJLDC(ctx context.Context, domain string, add func(string)) {
	reqURL := fmt.Sprintf("https://jldc.me/anonym-subdomains/%s", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", branding.UserAgent)

	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return
	}

	var names []string
	if err := json.Unmarshal(body, &names); err != nil {
		return
	}

	for _, name := range names {
		add(name)
	}
}

func (e *Engine) queryWaybackMachine(ctx context.Context, domain string, add func(string)) {
	reqURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", branding.UserAgent)

	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return
	}

	for _, row := range rows {
		if len(row) > 0 {
			u, err := url.Parse(row[0])
			if err == nil && u.Hostname() != "" {
				add(u.Hostname())
			}
		}
	}
}

func (e *Engine) queryCertSpotter(ctx context.Context, domain string, add func(string)) {
	reqURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", branding.UserAgent)

	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return
	}

	var items []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return
	}

	for _, item := range items {
		for _, name := range item.DNSNames {
			add(name)
		}
	}
}

func (e *Engine) queryThreatMiner(ctx context.Context, domain string, add func(string)) {
	reqURL := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", branding.UserAgent)

	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return
	}

	var data struct {
		Results []string `json:"results"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return
	}

	for _, name := range data.Results {
		add(name)
	}
}

func (e *Engine) querySubdomainCenter(ctx context.Context, domain string, add func(string)) {
	reqURL := fmt.Sprintf("https://api.subdomain.center/?domain=%s", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", branding.UserAgent)

	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return
	}

	var names []string
	if err := json.Unmarshal(body, &names); err != nil {
		return
	}

	for _, name := range names {
		add(name)
	}
}

func (e *Engine) probeLiveSubdomains(ctx context.Context, subdomains []string, wildcardIP string) ([]DiscoveredDomain, []string) {
	var mu sync.Mutex
	var liveDomains []DiscoveredDomain
	var allLiveURLs []string

	sem := make(chan struct{}, 30)
	var wg sync.WaitGroup

	for _, sub := range subdomains {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			// Filter out wildcard IP resolution if active
			if wildcardIP != "" && hostResolvesToIP(ctx, host, wildcardIP) {
				return
			}

			liveURLs := probeHostPorts(ctx, host)
			if len(liveURLs) > 0 {
				mu.Lock()
				liveDomains = append(liveDomains, DiscoveredDomain{
					Hostname: host,
					LiveURLs: liveURLs,
					Source:   "passive_osint",
				})
				allLiveURLs = append(allLiveURLs, liveURLs...)
				mu.Unlock()
			}
		}(sub)
	}

	wg.Wait()
	sort.Strings(allLiveURLs)
	return liveDomains, allLiveURLs
}

func probeHostPorts(ctx context.Context, host string) []string {
	ports := []struct {
		port   string
		scheme string
	}{
		{"443", "https"},
		{"80", "http"},
		{"8443", "https"},
		{"8080", "http"},
		{"8000", "http"},
		{"9090", "http"},
		{"3000", "http"},
		{"8888", "http"},
	}

	var live []string
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     dialer.DialContext,
	}
	client := &http.Client{
		Timeout:   4 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		targetURL := fmt.Sprintf("%s://%s", p.scheme, host)
		if p.port != "80" && p.port != "443" {
			targetURL = fmt.Sprintf("%s://%s:%s", p.scheme, host, p.port)
		}

		req, err := http.NewRequestWithContext(ctx, "HEAD", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", branding.UserAgent)

		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			live = append(live, targetURL)
			break // First responsive port is sufficient
		}
	}
	return live
}

func detectWildcardIP(ctx context.Context, rootDomain string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	randomHost := fmt.Sprintf("chk-%s.%s", hex.EncodeToString(b), rootDomain)

	addrs, err := net.DefaultResolver.LookupHost(ctx, randomHost)
	if err == nil && len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

func hostResolvesToIP(ctx context.Context, host, targetIP string) bool {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if addr == targetIP {
			return true
		}
	}
	return false
}

var reHostname = regexp.MustCompile(`^([a-zA-Z0-9_][a-zA-Z0-9_-]*\.)+[a-zA-Z]{2,}$`)

func isValidHostname(h string) bool {
	return reHostname.MatchString(h)
}
