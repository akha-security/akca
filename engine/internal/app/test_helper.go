package app

import (
	"context"
	"fmt"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/queue"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/session"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

// NewWithDB creates an engine backed by the provided database (integration tests).
func NewWithDB(writer events.Writer, db *storage.DB) (*Engine, error) {
	if err := db.Migrate(); err != nil {
		return nil, err
	}

	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = false
	cfg.ScanID = fmt.Sprintf("scan-%d", time.Now().Unix())
	scopeEngine := scope.NewEngine(cfg)
	limiter := ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit)
	client, err := httpclient.New(cfg, scopeEngine, limiter)
	if err != nil {
		return nil, err
	}

	batcher := events.NewBatcher(writer, 100, 250*time.Millisecond)
	oastCtx, oastCancel := context.WithCancel(context.Background())
	engine := &Engine{
		writer:     writer,
		batcher:    batcher,
		db:         db,
		session:    session.NewScanSession(cfg),
		scope:      scopeEngine,
		limiter:    limiter,
		client:     client,
		reqQueue:   queue.NewRequestQueue(),
		stopCh:     make(chan struct{}),
		oastCtx:    oastCtx,
		oastCancel: oastCancel,
	}
	if cfg.EnableOAST {
		listener, err := oast.NewListener(db, engine.Emit, oast.Config{
			ServerURL:    cfg.OASTServerURL,
			PollInterval: cfg.OASTPollInterval,
		})
		if err != nil {
			oastCancel()
			return nil, err
		}
		engine.oast = listener
		if err := listener.Start(oastCtx); err != nil {
			oastCancel()
			return nil, err
		}
	}
	engine.verifier = verification.NewEngine(db, engine.Emit)
	return engine, nil
}
