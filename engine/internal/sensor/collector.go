package sensor

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Source struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Location  string `json:"location"`
	Tainted   bool   `json:"tainted"`
	ValueHash string `json:"value_hash,omitempty"`
}

type Sink struct {
	Type          string   `json:"type"`
	Operation     string   `json:"operation"`
	Target        string   `json:"target,omitempty"`
	Tainted       bool     `json:"tainted"`
	Sanitized     bool     `json:"sanitized"`
	Parameterized bool     `json:"parameterized,omitempty"`
	Stack         []string `json:"stack,omitempty"`
}

type Event struct {
	TraceID     string    `json:"trace_id"`
	RequestID   string    `json:"request_id"`
	ScanID      string    `json:"scan_id"`
	CandidateID string    `json:"candidate_id"`
	Endpoint    string    `json:"endpoint"`
	Parameter   string    `json:"parameter"`
	Platform    string    `json:"platform"`
	Source      Source    `json:"source"`
	Sinks       []Sink    `json:"sinks"`
	ObservedAt  time.Time `json:"observed_at"`
}

type Binding struct {
	RequestID   string
	ScanID      string
	CandidateID string
	Endpoint    string
	Parameter   string
	Location    string
}

type Assessment struct {
	Vulnerable bool   `json:"vulnerable"`
	Safe       bool   `json:"safe"`
	Reason     string `json:"reason"`
	Sink       *Sink  `json:"sink,omitempty"`
}

type Store interface {
	SaveRuntimeTrace(traceID, scanID, requestID, candidateID, endpoint, parameter, verdict, traceJSON string) error
}

type Collector struct {
	mu       sync.RWMutex
	token    string
	bindings map[string]Binding
	events   map[string]Event
	traceIDs map[string]string
	ready    map[string]chan struct{}
	created  map[string]time.Time
	active   map[string]time.Time
	store    Store
}

func NewCollector(token string, store Store) *Collector {
	return &Collector{
		token: strings.TrimSpace(token), bindings: make(map[string]Binding),
		events: make(map[string]Event), traceIDs: make(map[string]string),
		ready: make(map[string]chan struct{}), created: make(map[string]time.Time),
		active: make(map[string]time.Time), store: store,
	}
}

func (c *Collector) Token() string {
	return c.token
}

func (c *Collector) ActivateEndpoint(rawURL string) {
	host := endpointHost(rawURL)
	if host == "" {
		return
	}
	c.mu.Lock()
	c.active[host] = time.Now()
	c.mu.Unlock()
}

func (c *Collector) ActiveFor(rawURL string) bool {
	host := endpointHost(rawURL)
	if host == "" {
		return false
	}
	c.mu.RLock()
	seen := c.active[host]
	c.mu.RUnlock()
	return !seen.IsZero() && time.Since(seen) < 30*time.Minute
}

func endpointHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Host)
}

func (c *Collector) Register(binding Binding) error {
	if strings.TrimSpace(binding.RequestID) == "" || strings.TrimSpace(binding.ScanID) == "" ||
		strings.TrimSpace(binding.CandidateID) == "" || strings.TrimSpace(binding.Endpoint) == "" {
		return fmt.Errorf("runtime trace binding is incomplete")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredLocked(time.Now().Add(-10 * time.Minute))
	if existing, duplicate := c.bindings[binding.RequestID]; duplicate && existing != binding {
		return fmt.Errorf("request ID is already bound to another candidate")
	}
	c.bindings[binding.RequestID] = binding
	if c.ready[binding.RequestID] == nil {
		c.ready[binding.RequestID] = make(chan struct{})
	}
	c.created[binding.RequestID] = time.Now()
	return nil
}

func (c *Collector) pruneExpiredLocked(cutoff time.Time) {
	for requestID, created := range c.created {
		if created.Before(cutoff) {
			delete(c.created, requestID)
			delete(c.bindings, requestID)
			delete(c.ready, requestID)
		}
	}
}

func (c *Collector) Ingest(event Event) (Assessment, error) {
	c.mu.RLock()
	binding, exists := c.bindings[event.RequestID]
	c.mu.RUnlock()
	if !exists || event.ScanID != binding.ScanID || event.CandidateID != binding.CandidateID ||
		event.Endpoint != binding.Endpoint || event.Parameter != binding.Parameter {
		return Assessment{}, fmt.Errorf("runtime trace correlation mismatch")
	}
	if event.TraceID == "" || event.Platform == "" || event.ObservedAt.IsZero() ||
		!strings.EqualFold(strings.TrimSpace(event.Source.Location), strings.TrimSpace(binding.Location)) ||
		!strings.EqualFold(strings.TrimSpace(event.Source.Name), strings.TrimSpace(binding.Parameter)) ||
		len(event.Sinks) == 0 || len(event.Sinks) > 128 ||
		event.ObservedAt.Before(time.Now().Add(-10*time.Minute)) ||
		event.ObservedAt.After(time.Now().Add(2*time.Minute)) {
		return Assessment{}, fmt.Errorf("runtime trace is incomplete")
	}
	assessment := Assess(event)
	redacted := redactEvent(event)
	c.mu.Lock()
	if existing, duplicate := c.events[event.RequestID]; duplicate {
		c.mu.Unlock()
		return Assess(existing), nil
	}
	if owner, exists := c.traceIDs[event.TraceID]; exists && owner != event.RequestID {
		c.mu.Unlock()
		return Assessment{}, fmt.Errorf("runtime trace ID is already bound to another request")
	}
	c.traceIDs[event.TraceID] = event.RequestID
	c.mu.Unlock()
	raw, err := json.Marshal(redacted)
	if err != nil {
		return Assessment{}, err
	}
	if c.store != nil {
		verdict := "inconclusive"
		if assessment.Vulnerable {
			verdict = "vulnerable"
		} else if assessment.Safe {
			verdict = "safe"
		}
		if err := c.store.SaveRuntimeTrace(event.TraceID, event.ScanID, event.RequestID, event.CandidateID,
			event.Endpoint, event.Parameter, verdict, string(raw)); err != nil {
			c.mu.Lock()
			delete(c.traceIDs, event.TraceID)
			c.mu.Unlock()
			return Assessment{}, err
		}
	}
	c.mu.Lock()
	if _, duplicate := c.events[event.RequestID]; !duplicate {
		c.events[event.RequestID] = redacted
		if ready := c.ready[event.RequestID]; ready != nil {
			close(ready)
			delete(c.ready, event.RequestID)
		}
	}
	delete(c.created, event.RequestID)
	delete(c.bindings, event.RequestID)
	c.mu.Unlock()
	return assessment, nil
}

func (c *Collector) Await(ctx context.Context, requestID string) (Event, Assessment, bool) {
	c.mu.RLock()
	if event, ok := c.events[requestID]; ok {
		c.mu.RUnlock()
		return event, Assess(event), true
	}
	ready := c.ready[requestID]
	c.mu.RUnlock()
	if ready == nil {
		return Event{}, Assessment{}, false
	}
	select {
	case <-ctx.Done():
		return Event{}, Assessment{}, false
	case <-ready:
		c.mu.RLock()
		event, ok := c.events[requestID]
		c.mu.RUnlock()
		return event, Assess(event), ok
	}
}

func redactEvent(event Event) Event {
	out := event
	out.Sinks = append([]Sink(nil), event.Sinks...)
	for index := range out.Sinks {
		if out.Sinks[index].Target != "" {
			sum := sha256.Sum256([]byte(out.Sinks[index].Target))
			out.Sinks[index].Target = "sha256:" + hex.EncodeToString(sum[:])
		}
		if len(out.Sinks[index].Stack) > 0 {
			sum := sha256.Sum256([]byte(strings.Join(out.Sinks[index].Stack, "\n")))
			out.Sinks[index].Stack = []string{"sha256:" + hex.EncodeToString(sum[:])}
		}
	}
	return out
}

func Assess(event Event) Assessment {
	if !event.Source.Tainted {
		return Assessment{Reason: "source was not marked tainted"}
	}
	var safeSink *Sink
	for index := range event.Sinks {
		sink := event.Sinks[index]
		if !sink.Tainted {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(sink.Type)) {
		case "sql":
			if sink.Parameterized || sink.Sanitized {
				copySink := sink
				safeSink = &copySink
				continue
			}
		case "command", "template", "file", "ldap", "xpath", "xml", "http", "deserialization":
			if sink.Sanitized {
				copySink := sink
				safeSink = &copySink
				continue
			}
		default:
			continue
		}
		copySink := sink
		return Assessment{Vulnerable: true, Reason: "tainted source reached an unsafe runtime sink", Sink: &copySink}
	}
	if safeSink != nil {
		reason := "tainted input reached a supported sink only through a sanitizer"
		if strings.EqualFold(safeSink.Type, "sql") && safeSink.Parameterized {
			reason = "tainted input reached SQL only through a parameterized bind"
		}
		return Assessment{Safe: true, Reason: reason, Sink: safeSink}
	}
	return Assessment{Reason: "no supported tainted sink was observed"}
}

func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/v1/health") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service": "akca-runtime-sensor-collector", "status": "ready",
		})
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/traces" {
		http.NotFound(w, r)
		return
	}
	provided := r.Header.Get("X-Akca-Sensor-Token")
	if c.token == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(c.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	defer r.Body.Close()
	var event Event
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		http.Error(w, "invalid trace", http.StatusBadRequest)
		return
	}
	assessment, err := c.Ingest(event)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(assessment)
}
