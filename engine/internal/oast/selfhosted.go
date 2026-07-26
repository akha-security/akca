package oast

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SelfHostedConfig enables only explicitly configured listeners. HTTPAddr may
// use 127.0.0.1:0 for an ephemeral local test listener; public deployments
// should provide a DNS name resolving to the listener and standard ports.
type SelfHostedConfig struct {
	Domain      string `json:"domain"`
	HTTPAddr    string `json:"http_addr,omitempty"`
	HTTPSAddr   string `json:"https_addr,omitempty"`
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `json:"tls_key_file,omitempty"`
	DNSAddr     string `json:"dns_addr,omitempty"`
	SMTPAddr    string `json:"smtp_addr,omitempty"`
	LDAPAddr    string `json:"ldap_addr,omitempty"`
}

type SelfHostedProvider struct {
	mu           sync.Mutex
	cfg          SelfHostedConfig
	domain       string
	interactions []Interaction
	servers      []*http.Server
	listeners    []net.Listener
	dns          net.PacketConn
	httpAddr     string
	stop         chan struct{}
	started      bool
	wg           sync.WaitGroup
	seq          int
}

func NewSelfHostedProvider(cfg SelfHostedConfig) *SelfHostedProvider {
	return &SelfHostedProvider{cfg: cfg, domain: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.Domain)), ".")}
}

func (p *SelfHostedProvider) Start() error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return nil
	}
	if p.domain == "" {
		p.mu.Unlock()
		return fmt.Errorf("self-hosted OAST domain is required")
	}
	if p.cfg.HTTPAddr == "" && p.cfg.HTTPSAddr == "" && p.cfg.DNSAddr == "" &&
		p.cfg.SMTPAddr == "" && p.cfg.LDAPAddr == "" {
		p.mu.Unlock()
		return fmt.Errorf("self-hosted OAST requires at least one listener")
	}
	p.stop = make(chan struct{})
	p.started = true
	p.mu.Unlock()

	if p.cfg.HTTPAddr != "" {
		if err := p.startHTTP(p.cfg.HTTPAddr, false); err != nil {
			_ = p.Stop()
			return err
		}
	}
	if p.cfg.HTTPSAddr != "" {
		if p.cfg.TLSCertFile == "" || p.cfg.TLSKeyFile == "" {
			_ = p.Stop()
			return fmt.Errorf("HTTPS OAST listener requires tls_cert_file and tls_key_file")
		}
		if err := p.startHTTP(p.cfg.HTTPSAddr, true); err != nil {
			_ = p.Stop()
			return err
		}
	}
	if p.cfg.DNSAddr != "" {
		if err := p.startDNS(p.cfg.DNSAddr); err != nil {
			_ = p.Stop()
			return err
		}
	}
	if p.cfg.SMTPAddr != "" {
		if err := p.startTCP(p.cfg.SMTPAddr, "smtp"); err != nil {
			_ = p.Stop()
			return err
		}
	}
	if p.cfg.LDAPAddr != "" {
		if err := p.startTCP(p.cfg.LDAPAddr, "ldap"); err != nil {
			_ = p.Stop()
			return err
		}
	}
	return nil
}

func (p *SelfHostedProvider) Stop() error {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return nil
	}
	p.started = false
	close(p.stop)
	servers := append([]*http.Server(nil), p.servers...)
	listeners := append([]net.Listener(nil), p.listeners...)
	dns := p.dns
	p.mu.Unlock()
	for _, server := range servers {
		_ = server.Close()
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	if dns != nil {
		_ = dns.Close()
	}
	p.wg.Wait()
	return nil
}

func (p *SelfHostedProvider) Domain() string { return p.domain }

func (p *SelfHostedProvider) GenerateURL(payloadID string) (GeneratedURL, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return GeneratedURL{}, fmt.Errorf("self-hosted OAST provider not started")
	}
	p.seq++
	nonce := make([]byte, 6)
	if _, err := rand.Read(nonce); err != nil {
		return GeneratedURL{}, err
	}
	token := fmt.Sprintf("%s-%d-%s", sanitizeToken(payloadID), p.seq, hex.EncodeToString(nonce))
	host := token + "." + p.domain
	callbackURL := "http://" + host + "/"
	if p.httpAddr != "" {
		addressHost, addressPort, _ := net.SplitHostPort(p.httpAddr)
		if ip := net.ParseIP(strings.Trim(addressHost, "[]")); ip != nil || strings.EqualFold(addressHost, "localhost") {
			callbackURL = "http://" + net.JoinHostPort(addressHost, addressPort) + "/c/" + url.PathEscape(token)
		} else if addressPort != "" && addressPort != "80" {
			callbackURL = "http://" + net.JoinHostPort(host, addressPort) + "/"
		}
	}
	return GeneratedURL{
		URL: callbackURL, Host: host, PayloadID: payloadID, CorrelationToken: token,
	}, nil
}

func (p *SelfHostedProvider) Poll() ([]Interaction, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := append([]Interaction(nil), p.interactions...)
	p.interactions = nil
	return out, nil
}

func (p *SelfHostedProvider) HTTPAddress() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.httpAddr
}

func (p *SelfHostedProvider) startHTTP(address string, tlsEnabled bool) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("OAST HTTP listen: %w", err)
	}
	protocol := "http"
	if tlsEnabled {
		protocol = "https"
	}
	server := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.handleHTTP(protocol, w, r) }),
		ReadHeaderTimeout: 5 * time.Second,
	}
	p.mu.Lock()
	p.listeners = append(p.listeners, listener)
	p.servers = append(p.servers, server)
	if !tlsEnabled {
		p.httpAddr = listener.Addr().String()
	}
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if tlsEnabled {
			_ = server.ServeTLS(listener, p.cfg.TLSCertFile, p.cfg.TLSKeyFile)
		} else {
			_ = server.Serve(listener)
		}
	}()
	return nil
}

func (p *SelfHostedProvider) handleHTTP(protocol string, w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/c/")
	token = strings.Trim(token, "/")
	if token == "" {
		token = ExtractCorrelationToken(strings.Split(r.Host, ":")[0], p.domain)
	}
	if token == "" {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<10))
	var raw strings.Builder
	raw.WriteString(r.Method + " " + r.URL.RequestURI() + "\n")
	for key, values := range r.Header {
		if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Cookie") {
			raw.WriteString(key + ": [REDACTED]\n")
			continue
		}
		raw.WriteString(key + ": " + strings.Join(values, ",") + "\n")
	}
	raw.Write(body)
	p.record(Interaction{
		Protocol: protocol, UniqueID: token + "." + p.domain, FullID: token + "." + p.domain,
		RemoteAddress: remoteHost(r.RemoteAddr), RawRequest: redactCallbackRaw(raw.String()),
		Timestamp: time.Now().UTC(),
	})
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNoContent)
}

func (p *SelfHostedProvider) startDNS(address string) error {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return fmt.Errorf("OAST DNS listen: %w", err)
	}
	p.mu.Lock()
	p.dns = conn
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		buffer := make([]byte, 4096)
		for {
			n, remote, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buffer[:n]...)
			name, questionEnd := parseDNSQuestion(packet)
			if name != "" {
				p.record(Interaction{
					Protocol: "dns", UniqueID: name, FullID: name,
					RemoteAddress: remoteHost(remote.String()), Timestamp: time.Now().UTC(),
				})
			}
			if questionEnd > 12 {
				response := append([]byte(nil), packet[:questionEnd]...)
				response[2], response[3] = 0x81, 0x83 // response + recursion available + NXDOMAIN
				response[6], response[7], response[8], response[9], response[10], response[11] = 0, 0, 0, 0, 0, 0
				_, _ = conn.WriteTo(response, remote)
			}
		}
	}()
	return nil
}

func (p *SelfHostedProvider) startTCP(address, protocol string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("OAST %s listen: %w", protocol, err)
	}
	p.mu.Lock()
	p.listeners = append(p.listeners, listener)
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if protocol == "smtp" {
					_, _ = io.WriteString(conn, "220 akca-oast ESMTP\r\n")
				}
				data, _ := io.ReadAll(io.LimitReader(conn, 16<<10))
				token := tokenFromBytes(data, p.domain)
				if token != "" {
					p.record(Interaction{
						Protocol: protocol, UniqueID: token + "." + p.domain, FullID: token + "." + p.domain,
						RemoteAddress: remoteHost(conn.RemoteAddr().String()),
						RawRequest:    redactCallbackRaw(string(data)), Timestamp: time.Now().UTC(),
					})
				}
			}()
		}
	}()
	return nil
}

func (p *SelfHostedProvider) record(interaction Interaction) {
	p.mu.Lock()
	p.interactions = append(p.interactions, interaction)
	p.mu.Unlock()
}

func parseDNSQuestion(packet []byte) (string, int) {
	if len(packet) < 17 {
		return "", 0
	}
	index := 12
	var labels []string
	for index < len(packet) {
		size := int(packet[index])
		index++
		if size == 0 {
			if index+4 > len(packet) {
				return "", 0
			}
			return strings.ToLower(strings.Join(labels, ".")), index + 4
		}
		if size > 63 || index+size > len(packet) {
			return "", 0
		}
		labels = append(labels, string(packet[index:index+size]))
		index += size
	}
	return "", 0
}

var callbackTokenRE = regexp.MustCompile(`[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_.-]+)`)

func tokenFromBytes(data []byte, domain string) string {
	for _, candidate := range callbackTokenRE.FindAllString(string(data), -1) {
		candidate = strings.TrimSuffix(strings.ToLower(candidate), ".")
		if strings.HasSuffix(candidate, "."+domain) {
			return ExtractCorrelationToken(candidate, domain)
		}
	}
	return ""
}

func redactCallbackRaw(raw string) string {
	raw = strings.ReplaceAll(raw, "\x00", "")
	lines := strings.Split(raw, "\n")
	for index, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "authorization:") || strings.HasPrefix(lower, "cookie:") ||
			strings.HasPrefix(lower, "set-cookie:") || strings.HasPrefix(lower, "proxy-authorization:") ||
			strings.HasPrefix(lower, "x-api-key:") || strings.HasPrefix(lower, "x-auth-token:") ||
			strings.HasPrefix(lower, "x-akca-sensor-token:") {
			if colon := strings.IndexByte(line, ':'); colon >= 0 {
				lines[index] = line[:colon+1] + " [REDACTED]"
			}
		}
	}
	redacted := strings.TrimSpace(strings.Join(lines, "\n"))
	redacted = callbackSecretRE.ReplaceAllString(redacted, `${1}[REDACTED]`)
	return callbackJSONSecretRE.ReplaceAllString(redacted, `${1}[REDACTED]${2}`)
}

var callbackSecretRE = regexp.MustCompile(`(?i)((?:token|secret|password|passwd|api[_-]?key|access[_-]?key|auth)=)[^&\s"'<>]+`)
var callbackJSONSecretRE = regexp.MustCompile(`(?i)("(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|auth)"\s*:\s*")[^"]*(")`)

func redactCallbackURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return callbackSecretRE.ReplaceAllString(raw, `${1}[REDACTED]`)
	}
	query := parsed.Query()
	for key, values := range query {
		lower := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
		switch lower {
		case "token", "secret", "password", "passwd", "apikey", "accesskey", "auth":
			for index := range values {
				values[index] = "[REDACTED]"
			}
			query[key] = values
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func redactSourceAddress(address string) string {
	if host, _, err := net.SplitHostPort(strings.TrimSpace(address)); err == nil {
		address = host
	}
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return net.IPv4(v4[0], v4[1], v4[2], 0).String() + "/24"
	}
	masked := ip.Mask(net.CIDRMask(64, 128))
	return masked.String() + "/64"
}

func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}
