package app

import "github.com/akha-security/akca/engine/internal/verification"

func (e *Engine) initVerifier() {
	if e.verifier == nil {
		e.verifier = verification.NewEngine(e.db, e.Emit)
	}
}

func (e *Engine) Verifier() *verification.Engine {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.verifier
}
