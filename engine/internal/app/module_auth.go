package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/auth"
	"github.com/akha-security/akca/engine/internal/browserpool"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/modules"
)

type moduleRoleComparer struct {
	mgr    *auth.Manager
	client *httpclient.Client
}

type moduleAuthResolver struct {
	mgr    *auth.Manager
	scanID string
}

func (e *Engine) moduleRunnerOpts() []modules.RunnerOption {
	var opts []modules.RunnerOption
	if e.session.Config.EnableBrowserWorkerPool {
		renderer := browserpool.NewHeadlessRendererWithProxy(
			e.session.Config.ProxyURL,
			e.session.Config.InsecureSkipVerify,
		)
		headers, cookies := browserSession(e.session.Config)
		renderer.SetSession(headers, cookies)
		if renderer.Available() {
			opts = append(opts, modules.WithBrowserRenderer(renderer))
		}
	}
	if e.platform != nil && e.platform.sensor != nil {
		opts = append(opts, modules.WithRuntimeSensor(e.platform.sensor))
	}
	if e.platform == nil || e.platform.auth == nil || e.client == nil {
		return opts
	}
	scanID := e.session.ID
	if scanID == "" {
		scanID = e.session.Config.ScanID
	}
	return append(opts,
		modules.WithRoleComparer(moduleRoleComparer{mgr: e.platform.auth, client: e.client}),
		modules.WithAuthResolver(moduleAuthResolver{mgr: e.platform.auth, scanID: scanID}),
	)
}

func (a moduleRoleComparer) CompareRoles(ctx context.Context, url string, roleA, roleB config.AuthProfile) (modules.RoleComparisonResult, error) {
	cmp, err := a.mgr.CompareRoles(ctx, a.client, url, roleA, roleB)
	if err != nil {
		return modules.RoleComparisonResult{}, err
	}
	return modules.RoleComparisonResult{
		RoleA: cmp.RoleA, RoleB: cmp.RoleB,
		StatusA: cmp.StatusA, StatusB: cmp.StatusB,
		AccessControl: cmp.AccessControl, Notes: cmp.Notes,
	}, nil
}

func (a moduleAuthResolver) ResolveProfile(profileID string) (config.AuthProfile, bool) {
	if a.mgr == nil || profileID == "" {
		return config.AuthProfile{}, false
	}
	profile, err := a.mgr.LoadProfile(a.scanID, profileID)
	if err != nil {
		return config.AuthProfile{}, false
	}
	return profile, true
}
