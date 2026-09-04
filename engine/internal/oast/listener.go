package oast

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/storage"
)

type Config struct {
	ServerURL          string
	PollInterval       time.Duration
	AllowLocalFallback bool
	SelfHosted         *SelfHostedConfig
	HTTPClient         *http.Client
}

type Listener struct {
	cfg          Config
	provider     Provider
	db           *storage.DB
	emit         EventSink
	mu           sync.RWMutex
	scanID       string
	correlations map[string]Correlation
	strengths    map[string]int
	stopCh       chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
}

func NewListener(db *storage.DB, emit EventSink, cfg Config) (*Listener, error) {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	var provider Provider
	if cfg.SelfHosted != nil {
		provider = NewSelfHostedProvider(*cfg.SelfHosted)
	} else if cfg.ServerURL != "" {
		provider = NewInteractshProviderWithClient(cfg.ServerURL, cfg.HTTPClient)
	} else {
		provider = NewLocalProvider()
	}
	return &Listener{
		cfg: cfg, provider: provider, db: db, emit: emit,
		correlations: make(map[string]Correlation),
		strengths:    make(map[string]int),
		stopCh:       make(chan struct{}),
	}, nil
}

func (l *Listener) ServerURL() string {
	if l.cfg.SelfHosted != nil {
		cfg := l.cfg.SelfHosted
		return "self-hosted://" + cfg.Domain + "|" + cfg.HTTPAddr + "|" + cfg.HTTPSAddr + "|" +
			cfg.DNSAddr + "|" + cfg.SMTPAddr + "|" + cfg.LDAPAddr
	}
	return l.cfg.ServerURL
}

func (l *Listener) Start(ctx context.Context) error {
	if err := l.startProvider(); err != nil {
		return err
	}
	payload := map[string]interface{}{
		"domain": l.provider.Domain(),
		"mode":   l.providerMode(),
	}
	if provider, ok := l.provider.(*InteractshProvider); ok {
		active, order, priority := provider.ServerSelection()
		payload["active_server"] = active
		payload["server_order"] = order
		payload["selected_priority"] = priority
		payload["fallback_used"] = priority > 1
		payload["fallback_stage"] = "startup_registration"
		payload["runtime_failover"] = false
	} else {
		// Self-hosted and local providers are exclusive; silently switching a
		// callback domain would break correlation and violate operator intent.
		payload["fallback_used"] = false
		payload["fallback_stage"] = "disabled"
		payload["runtime_failover"] = false
	}
	_ = l.emit("oast_started", "oast listener started", payload)
	l.wg.Add(1)
	go l.pollLoop(ctx)
	return nil
}

func (l *Listener) startProvider() error {
	err := l.provider.Start()
	if err == nil {
		return nil
	}
	if _, isLocal := l.provider.(*LocalProvider); isLocal {
		return err
	}
	remoteErr := err
	if !l.cfg.AllowLocalFallback {
		return fmt.Errorf("remote OAST unavailable: %w", remoteErr)
	}
	l.provider = NewLocalProvider()
	if err := l.provider.Start(); err != nil {
		return fmt.Errorf("remote OAST failed (%v) and local fallback failed (%v)", remoteErr, err)
	}
	_ = l.emit("oast_fallback", "remote OAST unavailable, using local provider", map[string]interface{}{
		"error": remoteErr.Error(),
	})
	return nil
}

func (l *Listener) RecordProbe(payload, location string, request httpclient.RequestRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().UTC()
	for token, correlation := range l.correlations {
		host := strings.TrimSuffix(strings.TrimPrefix(correlation.CallbackURL, "http://"), "/")
		host = strings.TrimSuffix(strings.TrimPrefix(host, "https://"), "/")
		if correlation.CallbackURL == "" || (!strings.Contains(payload, correlation.CallbackURL) && !strings.Contains(payload, host)) {
			continue
		}
		correlation.Payload = payload
		correlation.Location = location
		correlation.Method = request.Method
		correlation.Request = request
		correlation.ProbeSentAt = now
		l.correlations[token] = correlation
		return
	}
}

func (l *Listener) providerMode() string {
	if _, ok := l.provider.(*LocalProvider); ok {
		return "local"
	}
	if _, ok := l.provider.(*SelfHostedProvider); ok {
		return "self_hosted"
	}
	return "interactsh"
}

func (l *Listener) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopCh)
		l.wg.Wait()
		_ = l.provider.Stop()
		_ = l.emit("oast_stopped", "oast listener stopped", nil)
	})
}

func (l *Listener) SetScanID(scanID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.scanID != scanID {
		// Correlations are scan-scoped. Discarding the previous set prevents a
		// delayed callback from being attributed to the next scan.
		l.correlations = make(map[string]Correlation)
		l.strengths = make(map[string]int)
	}
	l.scanID = scanID
}

func (l *Listener) GenerateURL(payloadID, endpointURL, parameter, vulnClass string, findingID int64) (GeneratedURL, error) {
	return l.GenerateBoundURL(ProbeBinding{
		PayloadID: payloadID, EndpointURL: endpointURL, Parameter: parameter,
		Location: "unknown", VulnClass: vulnClass, FindingID: findingID,
	})
}

func (l *Listener) GenerateBoundURL(binding ProbeBinding) (GeneratedURL, error) {
	l.mu.RLock()
	scanID := strings.TrimSpace(l.scanID)
	l.mu.RUnlock()
	if scanID == "" {
		return GeneratedURL{}, fmt.Errorf("oast scan ID is required before generating a callback")
	}
	if strings.TrimSpace(binding.PayloadID) == "" || strings.TrimSpace(binding.EndpointURL) == "" ||
		strings.TrimSpace(binding.VulnClass) == "" || strings.TrimSpace(binding.Location) == "" {
		return GeneratedURL{}, fmt.Errorf("oast probe requires payload, endpoint, location, and vulnerability class")
	}
	nonceBytes := make([]byte, 12)
	if _, err := rand.Read(nonceBytes); err != nil {
		return GeneratedURL{}, fmt.Errorf("oast nonce generation: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	if strings.TrimSpace(binding.CandidateID) == "" {
		binding.CandidateID = "candidate-" + nonce
	}
	// Provider-visible IDs are always one-time values, including for providers
	// that otherwise derive their token only from the human-readable payload ID.
	providerPayloadID := binding.PayloadID + "-" + nonce
	gen, err := l.provider.GenerateURL(providerPayloadID)
	if err != nil {
		return GeneratedURL{}, err
	}
	gen.PayloadID = binding.PayloadID
	gen.CandidateID = binding.CandidateID
	gen.Nonce = nonce
	gen.CorrelationToken = strings.ToLower(strings.TrimSpace(gen.CorrelationToken))
	if gen.CorrelationToken == "" {
		return GeneratedURL{}, fmt.Errorf("oast provider returned an empty correlation token")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.scanID != scanID {
		return GeneratedURL{}, fmt.Errorf("oast scan changed while registering callback")
	}
	c := Correlation{
		ScanID: scanID, PayloadID: binding.PayloadID, CandidateID: binding.CandidateID,
		CorrelationToken: gen.CorrelationToken, Nonce: nonce,
		EndpointURL: binding.EndpointURL, Parameter: binding.Parameter, Location: binding.Location,
		VulnClass: binding.VulnClass, FindingID: binding.FindingID,
		CallbackURL: gen.URL, RegisteredAt: time.Now().UTC(),
	}
	l.correlations[gen.CorrelationToken] = c
	return gen, nil
}

func (l *Listener) Provider() Provider {
	return l.provider
}

func (l *Listener) pollLoop(ctx context.Context) {
	defer l.wg.Done()
	defer func() {
		if recovered := recover(); recovered != nil && l.emit != nil {
			_ = l.emit("oast_failed", fmt.Sprintf("OAST polling worker recovered from panic: %v", recovered), map[string]interface{}{
				"worker": "oast_poll", "runtime_failover": false,
			})
		}
	}()
	ticker := time.NewTicker(l.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.pollOnce()
		}
	}
}

func (l *Listener) pollOnce() {
	interactions, err := l.provider.Poll()
	if err != nil {
		_ = l.emit("oast_poll_error", err.Error(), nil)
		return
	}
	domain := l.provider.Domain()
	l.mu.RLock()
	correlations := make(map[string]Correlation, len(l.correlations))
	for k, v := range l.correlations {
		correlations[k] = v
	}
	l.mu.RUnlock()

	for _, interaction := range interactions {
		l.handleInteraction(interaction, domain, correlations)
	}
}

func (l *Listener) handleInteraction(interaction Interaction, domain string, correlations map[string]Correlation) {
	correlation, ok := MatchInteraction(interaction, domain, correlations)
	if !ok {
		return
	}
	strength := InteractionStrength(strings.ToLower(strings.TrimSpace(interaction.Protocol)))
	l.mu.Lock()
	activeScanID := l.scanID
	previousStrength := l.strengths[correlation.CorrelationToken]
	if activeScanID == "" || correlation.ScanID == "" || correlation.ScanID != activeScanID ||
		correlation.CandidateID == "" || correlation.Nonce == "" || strength == 0 ||
		(!interaction.Timestamp.IsZero() && interaction.Timestamp.Before(correlation.RegisteredAt.Add(-time.Minute))) ||
		previousStrength >= strength {
		l.mu.Unlock()
		return
	}
	l.strengths[correlation.CorrelationToken] = strength
	l.mu.Unlock()

	interaction = sanitizeInteraction(interaction)
	correlation = sanitizeCorrelation(correlation)
	record := CallbackRecord{
		ScanID: correlation.ScanID, PayloadID: correlation.PayloadID,
		Protocol: interaction.Protocol, SourceIP: interaction.RemoteAddress,
		Interaction: sanitizeInteraction(interaction), Correlation: correlation,
		Strength:   strength,
		ReceivedAt: time.Now().UTC(),
	}

	upgraded := false
	if l.db != nil {
		upgraded, _ = l.db.UpgradeFindingConfidenceOAST(correlation)
		record.ConfidenceUp = upgraded
		if err := l.db.SaveOASTCallback(correlation.ScanID, correlation.PayloadID, record); err != nil {
			l.mu.Lock()
			if previousStrength > 0 {
				l.strengths[correlation.CorrelationToken] = previousStrength
			} else {
				delete(l.strengths, correlation.CorrelationToken)
			}
			l.mu.Unlock()
			return
		}
	}
	record.ConfidenceUp = upgraded

	_ = l.emit("oast_callback_received", correlation.PayloadID, map[string]interface{}{
		"scan_id": correlation.ScanID, "payload_id": correlation.PayloadID,
		"endpoint": correlation.EndpointURL, "parameter": correlation.Parameter,
		"vuln_class": correlation.VulnClass, "protocol": interaction.Protocol,
		"source_ip": record.SourceIP, "timestamp": record.ReceivedAt,
		"confidence_upgraded": upgraded, "correlation": correlation,
	})
}

func sanitizeInteraction(interaction Interaction) Interaction {
	interaction.RemoteAddress = redactSourceAddress(interaction.RemoteAddress)
	if len(interaction.RawRequest) > 8<<10 {
		interaction.RawRequest = interaction.RawRequest[:8<<10]
	}
	return interaction
}

func sanitizeCorrelation(correlation Correlation) Correlation {
	return correlation
}

func (l *Listener) RegisterCorrelation(c Correlation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.correlations[strings.ToLower(strings.TrimSpace(c.CorrelationToken))] = c
}

func (l *Listener) CorrelationCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.correlations)
}

// RemainingDrainDuration keeps the configured callback window relative to the
// newest delivered probe instead of adding the full window again at scan end.
func (l *Listener) RemainingDrainDuration(window time.Duration) time.Duration {
	if l == nil || window <= 0 {
		return 0
	}
	l.mu.RLock()
	var newest time.Time
	for _, correlation := range l.correlations {
		probeTime := correlation.ProbeSentAt
		if probeTime.IsZero() {
			probeTime = correlation.RegisteredAt
		}
		if !probeTime.IsZero() && probeTime.After(newest) {
			newest = probeTime
		}
	}
	count := len(l.correlations)
	l.mu.RUnlock()
	if count == 0 || newest.IsZero() {
		return 0
	}
	remaining := window - time.Since(newest)
	if remaining > 0 {
		return remaining
	}
	interval := l.cfg.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if interval > 2*time.Second {
		interval = 2 * time.Second
	}
	return interval
}

// Drain actively polls for OAST interactions until duration elapses or ctx is cancelled.
func (l *Listener) Drain(ctx context.Context, duration time.Duration) {
	if duration <= 0 || l.provider == nil {
		return
	}
	deadline := time.Now().Add(duration)
	interval := l.cfg.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		default:
		}
		l.pollOnce()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		wait := interval
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-l.stopCh:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
