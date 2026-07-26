package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/apikeyvalidator"
	"github.com/akha-security/akca/engine/internal/auth"
	"github.com/akha-security/akca/engine/internal/benchmark"
	"github.com/akha-security/akca/engine/internal/browserpool"
	"github.com/akha-security/akca/engine/internal/checkpoint"
	"github.com/akha-security/akca/engine/internal/comparison"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/correlation"
	"github.com/akha-security/akca/engine/internal/logincapture"
	"github.com/akha-security/akca/engine/internal/observability"
	"github.com/akha-security/akca/engine/internal/packs"
	"github.com/akha-security/akca/engine/internal/proxy"
	"github.com/akha-security/akca/engine/internal/scheduler"
	"github.com/akha-security/akca/engine/internal/secrets"
	"github.com/akha-security/akca/engine/internal/sensor"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/workspace"
)

type Platform struct {
	mu           sync.Mutex
	auth         *auth.Manager
	checkpoint   *checkpoint.Store
	correlation  *correlation.Engine
	benchmark    *benchmark.Lab
	health       *observability.Collector
	packs        *packs.Manager
	browserPool  *browserpool.Pool
	proxy        *proxy.InterceptServer
	loginCapture *logincapture.Manager
	scheduler    *scheduler.Runner
	compare      *comparison.Engine
	apiKeys      *apikeyvalidator.Validator
	workspace    *workspace.API
	secrets      *secrets.Store
	sensor       *sensor.Collector
	sensorServer *sensor.Server
	platCtx      context.Context
	platCancel   context.CancelFunc
}

func platformDataDir() string {
	dir, err := storage.DataDir()
	if err != nil {
		return ""
	}
	return dir
}

func (e *Engine) initPlatform(dataDir string) {
	if e.platform != nil {
		return
	}
	secretStore := secrets.NewStore(string(e.session.Config.CredentialStorageMode), dataDir)
	_ = secrets.EnsureDataDir(dataDir)
	ctx, cancel := context.WithCancel(context.Background())
	e.platform = &Platform{
		auth:        auth.NewManager(e.db, secretStore),
		checkpoint:  checkpoint.NewStore(e.db),
		correlation: correlation.NewEngine(e.db),
		benchmark:   benchmark.NewLab(e.db),
		health:      observability.NewCollector(e.db),
		packs:       packs.NewManager(e.db),
		apiKeys:     apikeyvalidator.New(e.db),
		compare:     comparison.NewEngine(e.db),
		secrets:     secretStore,
		platCtx:     ctx,
		platCancel:  cancel,
	}
	wsDB := &workspaceDBAdapter{db: e.db}
	e.platform.workspace = workspace.NewAPI(wsDB)
	if e.session.Config.EnableScanScheduler {
		e.platform.scheduler = scheduler.NewRunner(e.db, func(cfg config.ScanConfig) error {
			if err := e.StartScan(cfg); err != nil {
				return err
			}
			return e.WaitScanDone(context.Background())
		})
		go e.platform.scheduler.Start(ctx)
	}
}

func (e *Engine) bootstrapPlatform(cfg config.ScanConfig) error {
	dataDir, _ := storage.DataDir()
	e.initPlatform(dataDir)
	e.resetPlatformWorkers()
	if e.platform.auth != nil {
		_ = e.platform.auth.PersistProfiles(cfg.ScanID, cfg)
	}
	if cfg.EnableBrowserWorkerPool {
		e.platform.browserPool = browserpool.NewPool(e.db, cfg.BrowserWorkerPoolSize)
		e.platform.browserPool.Start(e.platform.platCtx)
	}
	if cfg.EnableProxyInterceptMode {
		e.platform.proxy = proxy.NewInterceptServer(e.db, e.scope, "proxy-"+cfg.ScanID)
		_ = e.platform.proxy.Start("127.0.0.1:18080")
	}
	if cfg.EnableRuntimeSensor {
		token := os.Getenv(cfg.RuntimeSensorTokenEnv)
		if token == "" {
			var err error
			token, err = sensor.GenerateToken()
			if err != nil {
				_ = e.Emit("runtime_sensor_unavailable", "runtime sensor token generation failed",
					map[string]interface{}{"scan_id": cfg.ScanID, "error": err.Error()})
				return nil
			}
		}
		collector := sensor.NewCollector(token, e.db)
		server, err := sensor.StartServer(cfg.RuntimeSensorListenAddr, collector)
		if err != nil {
			_ = e.Emit("runtime_sensor_unavailable", "runtime sensor collector could not start; sensorless DAST continues",
				map[string]interface{}{"scan_id": cfg.ScanID, "error": fmt.Errorf("start runtime sensor collector: %w", err).Error()})
			return nil
		}
		e.platform.sensor = collector
		e.platform.sensorServer = server
		_ = e.Emit("runtime_sensor_started", "runtime sensor collector listening",
			map[string]interface{}{"scan_id": cfg.ScanID, "listen_addr": server.Addr()})
	}
	return nil
}

func (e *Engine) resetPlatformWorkers() {
	if e.platform == nil {
		return
	}
	if e.platform.browserPool != nil {
		e.platform.browserPool.Stop()
		e.platform.browserPool = nil
	}
	if e.platform.proxy != nil {
		e.platform.proxy.Stop()
		e.platform.proxy = nil
	}
	if e.platform.sensorServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = e.platform.sensorServer.Close(ctx)
		cancel()
		e.platform.sensorServer = nil
		e.platform.sensor = nil
	}
}

func (e *Engine) shutdownPlatform() {
	if e.platform == nil {
		return
	}
	if e.platform.loginCapture != nil {
		e.platform.loginCapture.StopAll()
	}
	e.resetPlatformWorkers()
	if e.platform.scheduler != nil {
		e.platform.scheduler.Stop()
	}
	if e.platform.platCancel != nil {
		e.platform.platCancel()
	}
}

func (e *Engine) checkpointPhase(scanID, phase string, completed []string, status map[string]string) {
	if !e.session.Config.EnableScanResume || e.platform == nil {
		return
	}
	cfgJSON, _ := json.Marshal(e.session.Config)
	_ = e.platform.checkpoint.Save(scanID, checkpoint.State{
		Phase: phase, Completed: completed, PhaseStatus: status,
		CrawlQueue:  e.reqQueue.Snapshot(),
		ModuleState: map[string]interface{}{"phase": phase},
		Config:      cfgJSON,
	})
}

func (e *Engine) finalizePlatform(scanID string) {
	if e.platform == nil {
		return
	}
	if e.session.Config.EnableFindingCorrelation {
		_, _ = e.platform.correlation.Run(scanID)
	}
	if e.session.Config.EnableHealthMonitoring {
		oastStatus := "disabled"
		if e.oast != nil {
			oastStatus = "listening"
		}
		_, _ = e.platform.health.Capture(scanID, map[string]float64{
			"crawler": 1.0, "fuzzing": 0.8, "vuln_modules": 1.2,
		}, oastStatus, map[string]int{"crawl": e.reqQueue.Len(), "browser": 0})
	}
}

type workspaceDBAdapter struct {
	db *storage.DB
}

func (a *workspaceDBAdapter) SaveWorkspace(id, name, raw string) error {
	return a.db.SaveWorkspace(id, name, raw)
}
func (a *workspaceDBAdapter) ListWorkspaces() ([]workspace.Workspace, error) {
	return nil, nil
}
func (a *workspaceDBAdapter) SaveMember(workspaceID, raw string) error {
	return a.db.SaveWorkspaceMember(workspaceID, raw)
}
func (a *workspaceDBAdapter) ListMembers(workspaceID string) ([]workspace.Member, error) {
	raws, err := a.db.ListWorkspaceMembers(workspaceID)
	if err != nil {
		return nil, err
	}
	var out []workspace.Member
	for _, raw := range raws {
		var m workspace.Member
		_ = json.Unmarshal([]byte(raw), &m)
		out = append(out, m)
	}
	return out, nil
}
func (a *workspaceDBAdapter) SaveAudit(workspaceID, action, actor, details string) error {
	return a.db.SaveWorkspaceAudit(workspaceID, action, actor, details)
}
func (a *workspaceDBAdapter) CheckPermission(workspaceID, email, perm string) bool {
	return a.db.WorkspacePermissionAllowed(workspaceID, email, perm)
}
