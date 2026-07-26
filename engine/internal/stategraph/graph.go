package stategraph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

type Node struct {
	ID             string            `json:"id"`
	ScanID         string            `json:"scan_id"`
	URL            string            `json:"url"`
	DOMFingerprint string            `json:"dom_fingerprint"`
	AuthIdentity   string            `json:"auth_identity"`
	Cookies        map[string]string `json:"cookies,omitempty"`
	SessionStorage map[string]string `json:"session_storage,omitempty"`
	LocalStorage   map[string]string `json:"local_storage,omitempty"`
	VisibleActions []string          `json:"visible_actions,omitempty"`
	Forms          []string          `json:"forms,omitempty"`
	APICalls       []string          `json:"api_calls,omitempty"`
	WebSockets     []string          `json:"websockets,omitempty"`
	ServiceWorkers []string          `json:"service_workers,omitempty"`
	DOMSinkEvents  []string          `json:"dom_sink_events,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
}

type Edge struct {
	ID              string      `json:"id"`
	ScanID          string      `json:"scan_id"`
	FromStateID     string      `json:"from_state_id,omitempty"`
	ToStateID       string      `json:"to_state_id"`
	Action          string      `json:"action"`
	Preconditions   []string    `json:"preconditions,omitempty"`
	RequestTemplate interface{} `json:"request_template,omitempty"`
	SideEffects     []string    `json:"side_effects,omitempty"`
	Reversible      bool        `json:"reversible"`
	CreatedAt       time.Time   `json:"created_at"`
}

type Graph struct {
	mu    sync.RWMutex
	db    *storage.DB
	nodes map[string]Node
	edges map[string]Edge
}

func New(db *storage.DB) *Graph {
	return &Graph{db: db, nodes: make(map[string]Node), edges: make(map[string]Edge)}
}

func (g *Graph) ObservePage(scanID, rawURL, html, identity string, apiCalls []string) (Node, error) {
	return g.ObserveBrowserPage(scanID, rawURL, html, identity, nil, nil, nil, nil, nil, apiCalls, nil)
}

func (g *Graph) ObserveBrowserPage(scanID, rawURL, html, identity string,
	cookies, sessionStorage, localStorage map[string]string, actions, forms, apiCalls, websockets []string) (Node, error) {
	return g.ObserveInstrumentedPage(scanID, rawURL, html, identity, cookies, sessionStorage, localStorage,
		actions, forms, apiCalls, websockets, nil, nil)
}

func (g *Graph) ObserveInstrumentedPage(scanID, rawURL, html, identity string,
	cookies, sessionStorage, localStorage map[string]string, actions, forms, apiCalls, websockets,
	serviceWorkers, domSinkEvents []string) (Node, error) {
	if identity == "" {
		identity = "anonymous"
	}
	node := Node{
		ScanID: scanID, URL: rawURL, DOMFingerprint: DOMFingerprint(html),
		AuthIdentity: identity, Cookies: cloneMap(cookies), SessionStorage: cloneMap(sessionStorage),
		LocalStorage: cloneMap(localStorage), VisibleActions: sortedUnique(actions), Forms: sortedUnique(forms),
		APICalls: sortedUnique(apiCalls), WebSockets: sortedUnique(websockets),
		ServiceWorkers: sortedUnique(serviceWorkers), DOMSinkEvents: sortedUnique(domSinkEvents),
		CreatedAt: time.Now().UTC(),
	}
	node.ID = stableID(scanID, rawURL, node.DOMFingerprint, identity)
	g.mu.Lock()
	g.nodes[node.ID] = node
	g.mu.Unlock()
	if g.db != nil {
		err := saveNode(g.db, node)
		return node, err
	}
	return node, nil
}

func cloneMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func (g *Graph) AddTransition(scanID, fromID, toID, action string, requestTemplate interface{},
	preconditions, sideEffects []string, reversible bool) (Edge, error) {
	edge := Edge{
		ScanID: scanID, FromStateID: fromID, ToStateID: toID, Action: action,
		RequestTemplate: requestTemplate, Preconditions: preconditions, SideEffects: sideEffects,
		Reversible: reversible, CreatedAt: time.Now().UTC(),
	}
	edge.ID = stableID(scanID, fromID, toID, action)
	g.mu.Lock()
	g.edges[edge.ID] = edge
	g.mu.Unlock()
	if g.db != nil {
		err := saveEdge(g.db, edge)
		return edge, err
	}
	return edge, nil
}

func (g *Graph) FindByURL(rawURL, identity string) (Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var newest Node
	found := false
	for _, node := range g.nodes {
		if node.URL == rawURL && node.AuthIdentity == identity && (!found || node.CreatedAt.After(newest.CreatedAt)) {
			newest, found = node, true
		}
	}
	return newest, found
}

var volatileHTMLRE = regexp.MustCompile(`(?is)(nonce|csrf|xsrf|request[-_]?id|trace[-_]?id)\s*=\s*["'][^"']+["']`)

func DOMFingerprint(html string) string {
	normalized := verification.NormalizeVolatileFields(html)
	normalized = volatileHTMLRE.ReplaceAllString(normalized, "$1=\"__VOLATILE__\"")
	normalized = strings.Join(strings.Fields(strings.ToLower(normalized)), " ")
	return stableID(normalized)
}

func StorageHash(cookies, session, local map[string]string) string {
	return stableID(canonicalMap(cookies), canonicalMap(session), canonicalMap(local))
}

func saveNode(db *storage.DB, node Node) error {
	actions, _ := json.Marshal(node.VisibleActions)
	forms, _ := json.Marshal(node.Forms)
	api, _ := json.Marshal(node.APICalls)
	ws, _ := json.Marshal(node.WebSockets)
	workers, _ := json.Marshal(node.ServiceWorkers)
	sinks, _ := json.Marshal(node.DOMSinkEvents)
	_, err := db.Conn().Exec(`
INSERT OR REPLACE INTO application_states
(id, scan_id, url, dom_fingerprint, auth_identity, storage_hash, actions_json, forms_json,
 api_calls_json, websocket_json, service_workers_json, dom_sink_events_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		node.ID, node.ScanID, node.URL, node.DOMFingerprint, node.AuthIdentity,
		StorageHash(node.Cookies, node.SessionStorage, node.LocalStorage),
		string(actions), string(forms), string(api), string(ws), string(workers), string(sinks),
		node.CreatedAt.Format(time.RFC3339Nano))
	return err
}

func saveEdge(db *storage.DB, edge Edge) error {
	request, _ := json.Marshal(edge.RequestTemplate)
	preconditions, _ := json.Marshal(edge.Preconditions)
	sideEffects, _ := json.Marshal(edge.SideEffects)
	_, err := db.Conn().Exec(`
INSERT OR REPLACE INTO state_transitions
(id, scan_id, from_state_id, to_state_id, action, request_template_json, preconditions_json, side_effects_json, reversible, created_at)
VALUES (?, ?, NULLIF(?,''), ?, ?, ?, ?, ?, ?, ?)`,
		edge.ID, edge.ScanID, edge.FromStateID, edge.ToStateID, edge.Action, string(request),
		string(preconditions), string(sideEffects), edge.Reversible, edge.CreatedAt.Format(time.RFC3339Nano))
	return err
}

func stableID(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func canonicalMap(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		out.WriteString(key)
		out.WriteByte('=')
		out.WriteString(values[key])
		out.WriteByte('\n')
	}
	return out.String()
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
