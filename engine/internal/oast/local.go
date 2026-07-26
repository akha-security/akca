package oast

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type LocalProvider struct {
	mu            sync.Mutex
	domain        string
	secret        string
	correlationID string
	interactions  []Interaction
	seq           int
	started       bool
}

func NewLocalProvider() *LocalProvider {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	cid := hex.EncodeToString(b)
	return &LocalProvider{
		domain:        cid + ".oast.akca.local",
		secret:        cid,
		correlationID: cid,
	}
}

func (p *LocalProvider) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = true
	return nil
}

func (p *LocalProvider) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = false
	return nil
}

func (p *LocalProvider) Domain() string {
	return p.domain
}

func (p *LocalProvider) GenerateURL(payloadID string) (GeneratedURL, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return GeneratedURL{}, fmt.Errorf("oast provider not started")
	}
	p.seq++
	token := fmt.Sprintf("%s.%x", sanitizeToken(payloadID), p.seq)
	host := token + "." + p.domain
	return GeneratedURL{
		URL:              "http://" + host + "/",
		Host:             host,
		PayloadID:        payloadID,
		CorrelationToken: token,
	}, nil
}

func (p *LocalProvider) Poll() ([]Interaction, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := append([]Interaction(nil), p.interactions...)
	p.interactions = nil
	return out, nil
}

func (p *LocalProvider) InjectInteraction(uniqueID, protocol, remote string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.interactions = append(p.interactions, Interaction{
		Protocol:      protocol,
		UniqueID:      uniqueID,
		FullID:        uniqueID,
		RemoteAddress: remote,
		Timestamp:     time.Now().UTC(),
	})
}

func sanitizeToken(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-':
			return r
		}
		return '-'
	}, s)
	if s == "" {
		return "payload"
	}
	if len(s) > 28 {
		s = s[:28]
	}
	return s
}
