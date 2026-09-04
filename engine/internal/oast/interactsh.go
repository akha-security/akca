package oast

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	interactshCorrelationLength = 20
	interactshNonceLength       = 13
	interactshRequestTimeout    = 5 * time.Second
)

type InteractshProvider struct {
	mu             sync.Mutex
	serverURL      string
	serverOrder    []string
	serverPriority int
	registered     []string
	httpClient     *http.Client
	domain         string
	secret         string
	correlationID  string
	token          string
	privateKey     *rsa.PrivateKey
	started        bool
}

func NewInteractshProvider(serverURL string) *InteractshProvider {
	return NewInteractshProviderWithClient(serverURL, nil)
}

func NewInteractshProviderWithClient(serverURL string, client *http.Client) *InteractshProvider {
	if client == nil {
		client = &http.Client{Timeout: interactshRequestTimeout}
	}
	return &InteractshProvider{
		serverURL:  strings.TrimSpace(serverURL),
		httpClient: client,
	}
}

func (p *InteractshProvider) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("oast key generation: %w", err)
	}
	correlationID, err := randomZBase32(interactshCorrelationLength)
	if err != nil {
		return fmt.Errorf("oast correlation id: %w", err)
	}
	secret, err := randomSecret()
	if err != nil {
		return fmt.Errorf("oast secret: %w", err)
	}
	publicKey, err := encodeInteractshPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("oast public key: %w", err)
	}
	payload, err := json.Marshal(map[string]string{
		"public-key": publicKey, "secret-key": secret, "correlation-id": correlationID,
	})
	if err != nil {
		return err
	}

	configured := strings.Split(p.serverURL, ",")
	p.serverOrder = p.serverOrder[:0]
	for _, candidate := range configured {
		if candidate = strings.TrimSpace(candidate); candidate != "" {
			p.serverOrder = append(p.serverOrder, candidate)
		}
	}
	p.serverPriority = 0
	p.registered = p.registered[:0]

	var failures []string
	for index, candidate := range p.serverOrder {
		serverURL, err := normalizeOASTServer(candidate)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if err := p.register(serverURL, payload); err != nil {
			failures = append(failures, serverURL+": "+err.Error())
			continue
		}
		u, _ := url.Parse(serverURL)
		nonce, err := randomZBase32(interactshNonceLength)
		if err != nil {
			return err
		}
		p.serverURL = serverURL
		p.serverPriority = index + 1
		p.registered = append(p.registered, serverURL)
		p.domain = correlationID + nonce + "." + u.Hostname()
		p.secret = secret
		p.correlationID = correlationID
		p.privateKey = privateKey
		p.started = true
		return nil
	}
	return fmt.Errorf("oast registration failed: %s", strings.Join(failures, "; "))
}

// ServerSelection reports the deterministic startup-time fallback decision.
// Priority is one-based and follows the comma-separated configuration order.
func (p *InteractshProvider) ServerSelection() (active string, order []string, priority int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.serverURL, append([]string(nil), p.serverOrder...), p.serverPriority
}

func (p *InteractshProvider) register(serverURL string, payload []byte) error {
	return p.doRegister(serverURL, payload)
}

func (p *InteractshProvider) doRegister(serverURL string, payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, serverURL+"/register", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("Authorization", p.token)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("register response decode: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(result.Message), "registration successful") {
		return fmt.Errorf("unexpected register response: %q", result.Message)
	}
	return nil
}

func (p *InteractshProvider) Stop() error {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return nil
	}
	servers := append([]string(nil), p.registered...)
	correlationID, secret, token := p.correlationID, p.secret, p.token
	p.started = false
	p.mu.Unlock()
	payload, _ := json.Marshal(map[string]string{
		"correlation-id": correlationID, "secret-key": secret,
	})
	for _, serverURL := range servers {
		req, err := http.NewRequest(http.MethodPost, serverURL+"/deregister", bytes.NewReader(payload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			if token != "" {
				req.Header.Set("Authorization", token)
			}
			if resp, doErr := p.httpClient.Do(req); doErr == nil {
				_ = resp.Body.Close()
			}
		}
	}
	return nil
}

func (p *InteractshProvider) Domain() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.domain
}

func (p *InteractshProvider) GenerateURL(payloadID string) (GeneratedURL, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return GeneratedURL{}, fmt.Errorf("oast provider not started")
	}
	if strings.TrimSpace(p.domain) == "" {
		return GeneratedURL{}, fmt.Errorf("oast provider has no domain")
	}
	nonce, err := randomZBase32(10)
	if err != nil {
		return GeneratedURL{}, fmt.Errorf("oast payload nonce: %w", err)
	}
	unique := sanitizeToken(payloadID) + "-" + nonce
	host := unique + "." + p.domain
	return GeneratedURL{
		URL: "http://" + host + "/", Host: host, PayloadID: payloadID, CorrelationToken: unique,
	}, nil
}

func (p *InteractshProvider) Poll() ([]Interaction, error) {
	p.mu.Lock()
	servers := append([]string(nil), p.registered...)
	active := p.serverURL
	started := p.started
	p.mu.Unlock()
	if !started || len(servers) == 0 {
		return nil, fmt.Errorf("oast provider not started")
	}
	var interactions []Interaction
	var failures []string
	activeFailed := false
	successfulPolls := 0
	for _, serverURL := range servers {
		items, err := p.pollServer(serverURL)
		if err != nil {
			failures = append(failures, serverURL+": "+err.Error())
			if serverURL == active {
				activeFailed = true
			}
			continue
		}
		successfulPolls++
		interactions = append(interactions, items...)
	}
	if activeFailed {
		if failoverErr := p.failoverAfterPollError(); failoverErr != nil {
			failures = append(failures, "runtime failover: "+failoverErr.Error())
		} else {
			p.mu.Lock()
			newActive := p.serverURL
			p.mu.Unlock()
			items, err := p.pollServer(newActive)
			if err != nil {
				failures = append(failures, newActive+": "+err.Error())
			} else {
				successfulPolls++
				interactions = append(interactions, items...)
			}
		}
	}
	if successfulPolls == 0 {
		return nil, fmt.Errorf("oast polling failed: %s", strings.Join(failures, "; "))
	}
	return interactions, nil
}

func (p *InteractshProvider) pollServer(serverURL string) ([]Interaction, error) {
	p.mu.Lock()
	secret := p.secret
	correlationID := p.correlationID
	privateKey := p.privateKey
	token := p.token
	started := p.started
	p.mu.Unlock()
	if !started || privateKey == nil {
		return nil, fmt.Errorf("oast provider not started")
	}

	pollURL := fmt.Sprintf("%s/poll?id=%s&secret=%s", serverURL, url.QueryEscape(correlationID), url.QueryEscape(secret))
	req, err := http.NewRequest(http.MethodGet, pollURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("oast poll returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Data    []json.RawMessage `json:"data"`
		Extra   []string          `json:"extra"`
		AESKey  string            `json:"aes_key"`
		TLDData []string          `json:"tlddata"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("oast poll decode: %w", err)
	}

	interactions := make([]Interaction, 0, len(payload.Data)+len(payload.Extra)+len(payload.TLDData))
	for _, item := range payload.Data {
		plain := item
		if len(item) > 0 && item[0] == '"' {
			var encrypted string
			if err := json.Unmarshal(item, &encrypted); err != nil {
				continue
			}
			decrypted, err := decryptInteractshMessage(privateKey, payload.AESKey, encrypted)
			if err != nil {
				continue
			}
			plain = bytes.TrimSpace(decrypted)
		}
		if interaction, ok := decodeInteraction(plain); ok {
			interactions = append(interactions, interaction)
		}
	}
	for _, item := range append(payload.Extra, payload.TLDData...) {
		if interaction, ok := decodeInteraction([]byte(item)); ok {
			interactions = append(interactions, interaction)
		}
	}
	return interactions, nil
}

// failoverAfterPollError re-registers the existing correlation credentials on
// the next configured server. New payload URLs use the replacement domain;
// already-issued URLs remain valid if the original service recovers.
func (p *InteractshProvider) failoverAfterPollError() error {
	p.mu.Lock()
	order := append([]string(nil), p.serverOrder...)
	start := p.serverPriority // one-based active priority == next zero-based index
	privateKey := p.privateKey
	secret := p.secret
	correlationID := p.correlationID
	p.mu.Unlock()
	if privateKey == nil || start >= len(order) {
		return fmt.Errorf("no remaining OAST server")
	}
	publicKey, err := encodeInteractshPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{
		"public-key": publicKey, "secret-key": secret, "correlation-id": correlationID,
	})
	if err != nil {
		return err
	}
	var failures []string
	for index := start; index < len(order); index++ {
		serverURL, normalizeErr := normalizeOASTServer(order[index])
		if normalizeErr != nil {
			failures = append(failures, normalizeErr.Error())
			continue
		}
		if registerErr := p.register(serverURL, payload); registerErr != nil {
			failures = append(failures, serverURL+": "+registerErr.Error())
			continue
		}
		u, _ := url.Parse(serverURL)
		nonce, nonceErr := randomZBase32(interactshNonceLength)
		if nonceErr != nil {
			return nonceErr
		}
		p.mu.Lock()
		p.serverURL = serverURL
		p.serverPriority = index + 1
		p.domain = correlationID + nonce + "." + u.Hostname()
		alreadyRegistered := false
		for _, registered := range p.registered {
			if registered == serverURL {
				alreadyRegistered = true
				break
			}
		}
		if !alreadyRegistered {
			p.registered = append(p.registered, serverURL)
		}
		p.started = true
		p.mu.Unlock()
		return nil
	}
	return fmt.Errorf("%s", strings.Join(failures, "; "))
}

func decodeInteraction(data []byte) (Interaction, bool) {
	var interaction Interaction
	if err := json.Unmarshal(data, &interaction); err != nil {
		return Interaction{}, false
	}
	return interaction, interaction.UniqueID != "" || interaction.FullID != ""
}

func decryptInteractshMessage(privateKey *rsa.PrivateKey, encodedKey, encodedMessage string) ([]byte, error) {
	keyCiphertext, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, keyCiphertext, nil)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("oast ciphertext is too short")
	}
	plain := make([]byte, len(ciphertext)-aes.BlockSize)
	cipher.NewCTR(block, ciphertext[:aes.BlockSize]).XORKeyStream(plain, ciphertext[aes.BlockSize:])
	return plain, nil
}

func encodeInteractshPublicKey(publicKey *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
	return base64.StdEncoding.EncodeToString(pemData), nil
}

func normalizeOASTServer(raw string) (string, error) {
	raw = strings.TrimSpace(strings.TrimRight(raw, "/"))
	if raw == "" {
		return "", fmt.Errorf("empty OAST server")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("invalid OAST server %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported OAST scheme %q", u.Scheme)
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return strings.TrimRight(u.String(), "/"), nil
}

func randomSecret() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func randomZBase32(length int) (string, error) {
	const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	for i := range data {
		data[i] = alphabet[int(data[i])%len(alphabet)]
	}
	return string(data), nil
}

// MockInteractshServer provides a plaintext-compatible API for unit tests.
type MockInteractshServer struct {
	mu            sync.Mutex
	server        *http.Server
	URL           string
	domain        string
	secret        string
	correlationID string
	interactions  []Interaction
}

func NewMockInteractshServer() *MockInteractshServer {
	m := &MockInteractshServer{secret: "test-secret", correlationID: "corr-test", domain: "corr-test.oast.mock"}
	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var request map[string]string
		_ = json.NewDecoder(r.Body).Decode(&request)
		m.mu.Lock()
		m.secret = request["secret-key"]
		m.correlationID = request["correlation-id"]
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		data := append([]Interaction(nil), m.interactions...)
		m.interactions = nil
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
	})
	mux.HandleFunc("/deregister", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	m.server = &http.Server{Handler: mux}
	return m
}

func (m *MockInteractshServer) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	m.URL = "http://" + ln.Addr().String()
	go func() { _ = m.server.Serve(ln) }()
	return nil
}

func (m *MockInteractshServer) Close() error {
	if m.server == nil {
		return nil
	}
	return m.server.Close()
}

func (m *MockInteractshServer) PushInteraction(interaction Interaction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interactions = append(m.interactions, interaction)
}

func (m *MockInteractshServer) Domain() string { return m.domain }
