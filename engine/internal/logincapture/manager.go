package logincapture

import (
	"sync"
)

// Manager tracks active login capture sessions outside of scan lifecycle.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*CaptureServer
}

func NewManager() *Manager {
	return &Manager{sessions: map[string]*CaptureServer{}}
}

func (m *Manager) Register(id string, srv *CaptureServer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.sessions[id]; ok {
		_ = old.Stop()
	}
	m.sessions[id] = srv
}

func (m *Manager) Get(id string) (*CaptureServer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (m *Manager) Stop(id string) (Session, bool) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return Session{}, false
	}
	_ = s.Stop()
	return s.Session(), true
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Stop(id)
	}
}
