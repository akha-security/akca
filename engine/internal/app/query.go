package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/modules"
	"github.com/akha-security/akca/engine/internal/packs"
	"github.com/akha-security/akca/engine/internal/report"
	"github.com/akha-security/akca/engine/internal/storage"
)

func (e *Engine) HandleQuery(input CommandInput) error {
	sess := e.currentSession()
	scanID := sess.ID
	if scanID == "" {
		scanID = sess.Config.ScanID
	}
	var params map[string]interface{}
	if len(input.Params) > 0 {
		if err := json.Unmarshal(input.Params, &params); err != nil {
			return fmt.Errorf("validation error: failed to parse query params JSON (query: %q, request_id: %q): %w", input.Query, input.RequestID, err)
		}
	}
	if id := strParam(params, "scan_id"); id != "" {
		scanID = id
	}
	emit := func(data interface{}) error {
		return e.Emit("query_result", "query result", map[string]interface{}{
			"request_id": input.RequestID,
			"query":      input.Query,
			"data":       data,
		})
	}

	switch input.Query {
	case "endpoints":
		limit := ValidatedLimit(params, "limit", 50, 10000)
		q := storage.EndpointQuery{ScanID: scanID, Limit: limit, Cursor: int64Param(params, "cursor", 0),
			Search: strParam(params, "search"), Method: strParam(params, "method"), Status: strParam(params, "status"),
			SortBy: strParam(params, "sort_by"), SortDesc: boolParam(params, "sort_desc")}
		rows, cursor, err := e.db.ListEndpointsUI(q)
		if err != nil {
			return err
		}
		total, _ := e.db.CountEndpoints(scanID)
		return emit(map[string]interface{}{"rows": rows, "next_cursor": cursor, "total": total})
	case "endpoint_detail":
		id := int64Param(params, "endpoint_id", 0)
		detail, err := e.db.GetEndpointDetailUI(id)
		if err != nil {
			return err
		}
		return emit(detail)
	case "findings":
		limit := ValidatedLimit(params, "limit", 50, 10000)
		q := storage.FindingQuery{
			ScanID: scanID, Limit: limit, Cursor: int64Param(params, "cursor", 0),
			Search: strParam(params, "search"), Status: strParam(params, "status"), SortBy: strParam(params, "sort_by"),
			Severities: strSlice(params, "severities"), Confidences: strSlice(params, "confidences"),
			VulnClasses: strSlice(params, "vuln_classes"),
		}
		rows, cursor, err := e.db.ListFindingsUI(q)
		if err != nil {
			return err
		}
		return emit(map[string]interface{}{"rows": rows, "next_cursor": cursor})
	case "finding_detail":
		id := int64Param(params, "finding_id", 0)
		detail, err := e.db.GetFindingDetailUI(id)
		if err != nil {
			return err
		}
		return emit(detail)
	case "evidence_list":
		fid := int64Param(params, "finding_id", 0)
		if fid > 0 {
			if resolved, err := e.db.GetFindingScanID(fid); err == nil && resolved != "" {
				scanID = resolved
			}
		}
		rows, err := e.db.ListEvidenceLazy(scanID, fid)
		if err != nil {
			return err
		}
		return emit(rows)
	case "evidence_body":
		id := int64Param(params, "evidence_id", 0)
		body, err := e.db.LoadEvidenceBody(id)
		if err != nil {
			return err
		}
		return emit(body)
	case "request_response":
		id := int64Param(params, "request_id", 0)
		rec, err := e.db.LoadRequestResponseLazy(id)
		if err != nil {
			return err
		}
		return emit(rec)
	case "fuzz_dashboard":
		d, err := e.db.FuzzDashboardUI(scanID)
		if err != nil {
			return err
		}
		return emit(d)
	case "actuator_exposures":
		rows, err := e.db.ListFuzzByCategory(scanID, "actuator", intParam(params, "limit", 100))
		if err != nil {
			return err
		}
		return emit(rows)
	case "archive_exposures":
		rows, err := e.db.ListFuzzByCategory(scanID, "archive", intParam(params, "limit", 100))
		if err != nil {
			return err
		}
		return emit(rows)
	case "bypass403":
		rows, err := e.db.ListBypass403UI(scanID, intParam(params, "limit", 100))
		if err != nil {
			return err
		}
		return emit(rows)
	case "oast_callbacks":
		rows, err := e.db.ListOASTCallbackRecords(scanID, intParam(params, "limit", 100))
		if err != nil {
			return err
		}
		return emit(rows)
	case "runtime_traces":
		rows, err := e.db.ListRuntimeTraces(scanID, ValidatedLimit(params, "limit", 100, 1000))
		if err != nil {
			return err
		}
		return emit(rows)
	case "target_map":
		nodes, err := e.db.TargetMapUI(scanID)
		if err != nil {
			return err
		}
		return emit(nodes)
	case "timeline":
		rows, err := e.db.ListTimelineUI(scanID, strParam(params, "event_type"), intParam(params, "limit", 200))
		if err != nil {
			return err
		}
		return emit(rows)
	case "finding_groups":
		rows, err := e.db.ListFindingGroupsUI(scanID)
		if err != nil {
			return err
		}
		return emit(rows)
	case "merge_finding_groups":
		e.mu.Lock()
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		platform := e.platform
		e.mu.Unlock()
		if platform == nil {
			return fmt.Errorf("platform initialization failed")
		}
		err := platform.correlation.MergeGroups(scanID, strParam(params, "source_root"), strParam(params, "target_root"))
		if err != nil {
			return err
		}
		rows, err := e.db.ListFindingGroupsUI(scanID)
		if err != nil {
			return fmt.Errorf("database failure listing finding groups after merge: %w", err)
		}
		return emit(rows)
	case "split_finding_group":
		e.mu.Lock()
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		platform := e.platform
		e.mu.Unlock()
		if platform == nil {
			return fmt.Errorf("platform initialization failed")
		}
		err := platform.correlation.SplitGroup(scanID, strParam(params, "root_cause"), strParam(params, "finding_title"))
		if err != nil {
			return err
		}
		rows, err := e.db.ListFindingGroupsUI(scanID)
		if err != nil {
			return fmt.Errorf("database failure listing finding groups after split: %w", err)
		}
		return emit(rows)
	case "save_annotation":
		fid := int64Param(params, "finding_id", 0)
		err := e.db.SaveAnnotation(fid, strParam(params, "annotation_type"), strParam(params, "notes"), strParam(params, "annotated_by"))
		if err != nil {
			return err
		}
		anns, err := e.db.ListAnnotations(fid)
		if err != nil {
			return fmt.Errorf("database failure listing annotations after save: %w", err)
		}
		return emit(map[string]interface{}{"annotations": anns})
	case "generate_report":
		return e.generateReportQuery(input, params)
	case "export_report":
		return e.exportReportQuery(input, params, scanID)
	case "health_metrics":
		m, err := e.db.HealthMetricsUI(scanID)
		if err != nil {
			return err
		}
		return emit(m)
	case "recon":
		snap, err := e.db.GetReconUI(scanID)
		if err != nil {
			return err
		}
		return emit(snap)
	case "benchmark_results":
		_ = e.db.SeedBenchmarkIfEmpty()
		limit := ValidatedLimit(params, "limit", 20, 1000)
		rows, err := e.db.ListBenchmarkResults(limit)
		if err != nil {
			return err
		}
		return emit(rows)
	case "browser_workers":
		rows, err := e.db.ListBrowserWorkers()
		if err != nil {
			return err
		}
		return emit(rows)
	case "shadow_api_diffs":
		rows, err := e.db.ListShadowAPIDiffs(
			scanID, strParam(params, "kind"), ValidatedLimit(params, "limit", 200, 10000),
		)
		if err != nil {
			return err
		}
		return emit(rows)
	case "pack_versions":
		rows, err := e.db.ListPackVersions(strParam(params, "pack_type"))
		if err != nil {
			return err
		}
		return emit(rows)
	case "scheduled_scans":
		rows, err := e.db.ListScheduledScans()
		if err != nil {
			return err
		}
		return emit(rows)
	case "scheduled_runs":
		limit := ValidatedLimit(params, "limit", 20, 1000)
		rows, err := e.db.ListScheduledRuns(strParam(params, "schedule_id"), limit)
		if err != nil {
			return err
		}
		return emit(rows)
	case "save_scheduled_scan":
		id := strParam(params, "id")
		if id == "" {
			id = fmt.Sprintf("sched-%d", time.Now().Unix())
		}
		cfg, _ := json.Marshal(params["config"])
		if len(cfg) == 0 || string(cfg) == "null" {
			cfg = []byte("{}")
		}
		err := e.db.SaveScheduledScan(id, strParam(params, "cron_expression"), string(cfg), boolParam(params, "enabled"))
		if err != nil {
			return err
		}
		return emit(map[string]interface{}{"id": id, "preview": storage.CronHumanPreview(strParam(params, "cron_expression"))})
	case "delete_scheduled_scan":
		err := e.db.DeleteScheduledScan(strParam(params, "id"))
		if err != nil {
			return err
		}
		return emit(map[string]interface{}{"deleted": strParam(params, "id")})
	case "compare_scans":
		if e.platform != nil && e.platform.compare != nil {
			diff, err := e.platform.compare.Compare(strParam(params, "previous_scan_id"), strParam(params, "current_scan_id"))
			if err != nil {
				return err
			}
			return emit(diff)
		}
		diff, err := e.db.CompareScansUI(strParam(params, "previous_scan_id"), strParam(params, "current_scan_id"))
		if err != nil {
			return err
		}
		return emit(diff)
	case "run_benchmark":
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		results, err := e.platform.benchmark.RunAll()
		if err != nil {
			return err
		}
		return emit(map[string]interface{}{"results": results})
	case "install_pack":
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		man, err := e.platform.packs.Install(strParam(params, "pack_type"), strParam(params, "channel"), strParam(params, "version"), strParam(params, "payload"))
		if err != nil {
			return err
		}
		return emit(man)
	case "trust_pack_key":
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		if err := e.platform.packs.TrustKey(strParam(params, "key_id"), strParam(params, "public_key")); err != nil {
			return err
		}
		return emit(map[string]interface{}{"status": "trusted", "key_id": strParam(params, "key_id")})
	case "install_signed_pack":
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		raw, err := json.Marshal(params["manifest"])
		if err != nil {
			return err
		}
		var manifest packs.Manifest
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return fmt.Errorf("invalid signed pack manifest: %w", err)
		}
		installed, err := e.platform.packs.InstallSigned(
			manifest, strParam(params, "payload"), strParam(params, "engine_compatibility"),
		)
		if err != nil {
			return err
		}
		return emit(installed)
	case "rollback_pack":
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		err := e.platform.packs.Rollback(strParam(params, "pack_type"), strParam(params, "channel"), strParam(params, "version"))
		if err != nil {
			return err
		}
		return emit(map[string]interface{}{"status": "rolled_back"})
	case "auth_profiles":
		rows, err := e.db.ListAuthProfileRecords(scanID, intParam(params, "limit", 50))
		if err != nil {
			return err
		}
		return emit(rows)
	case "save_auth_profile":
		raw, _ := json.Marshal(params["profile"])
		err := e.db.SaveAuthProfile(scanID, strParam(params, "id"), strParam(params, "name"), string(raw))
		if err != nil {
			return err
		}
		return emit(map[string]interface{}{"saved": strParam(params, "id")})
	case "validate_api_key":
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		res, err := e.platform.apiKeys.Validate(context.Background(), scanID, strParam(params, "token"))
		if err != nil {
			return fmt.Errorf("failed to validate API key: %w", err)
		}
		return emit(res)
	case "proxy_traffic":
		rows, err := e.db.ListProxyTraffic(strParam(params, "session_id"), intParam(params, "limit", 100))
		if err != nil {
			return err
		}
		return emit(rows)
	case "proxy_forward":
		if e.platform == nil || e.platform.proxy == nil {
			return e.Emit("scan_error", "proxy intercept not enabled", map[string]interface{}{"request_id": input.RequestID})
		}
		rec, err := e.platform.proxy.Forward(context.Background(), strParam(params, "method"), strParam(params, "url"), strParam(params, "body"), mapString(params, "headers"))
		if err != nil {
			return err
		}
		return emit(rec)
	case "workspace_create":
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		ws, err := e.platform.workspace.CreateWorkspace(strParam(params, "name"))
		if err != nil {
			return err
		}
		return emit(ws)
	case "workspace_members":
		if e.platform == nil {
			e.initPlatform(platformDataDir())
		}
		members, err := e.platform.workspace.List(strParam(params, "workspace_id"))
		if err != nil {
			return err
		}
		return emit(members)
	case "command_center_history":
		rows, err := e.db.ListCommandCenterRequests(scanID, intParam(params, "limit", 100))
		if err != nil {
			return err
		}
		return emit(rows)
	case "command_center_send":
		result, err := e.ReplayRequest(params)
		if err != nil {
			return err
		}
		return emit(result)
	case "test_payload":
		result, err := e.ReplayRequest(map[string]interface{}{
			"method":  strParam(params, "method"),
			"url":     strParam(params, "url"),
			"body":    strParam(params, "payload"),
			"headers": params["headers"],
		})
		if err != nil {
			return err
		}
		return emit(result)
	case "save_payload_library":
		err := e.db.SavePayloadLibraryItem(strParam(params, "name"), strParam(params, "payload"))
		if err != nil {
			return err
		}
		items, _ := e.db.ListPayloadLibraryItems(100)
		return emit(items)
	case "payload_library":
		items, err := e.db.ListPayloadLibraryItems(intParam(params, "limit", 100))
		if err != nil {
			return err
		}
		return emit(items)
	case "get_data_directory":
		dir, err := e.GetDataDirectory()
		if err != nil {
			return err
		}
		return emit(map[string]interface{}{"path": dir})
	case "set_data_directory":
		dir, err := e.SetDataDirectory(strParam(params, "path"))
		if err != nil {
			return err
		}
		return emit(map[string]interface{}{"path": dir, "restart_required": true})
	case "module_catalog":
		return emit(map[string]interface{}{"modules": modules.ModuleCatalog()})
	case "start_login_capture", "poll_login_session", "stop_login_capture", "automated_login", "apply_login_session":
		return e.handleLoginQuery(input, params, emit)
	default:
		return e.Emit("scan_error", fmt.Sprintf("unknown query: %s", input.Query), map[string]interface{}{
			"request_id": input.RequestID,
		})
	}
}

// exportReportQuery streams a report to disk and returns the file path so large
// scans do not OOM the engine or IPC channel.
func (e *Engine) exportReportQuery(input CommandInput, params map[string]interface{}, scanID string) error {
	opts := report.Options{
		ScanID:      scanID,
		Template:    report.TemplateKind(strParam(params, "template")),
		Format:      report.Format(strParam(params, "format")),
		Partial:     boolParam(params, "partial"),
		Redact:      false,
		Severities:  strSlice(params, "severities"),
		Confidences: strSlice(params, "confidences"),
	}
	if opts.ScanID == "" {
		opts.ScanID = e.currentSession().Config.ScanID
	}
	if opts.Template == "" {
		opts.Template = report.TemplateInternal
	}
	if opts.Format == "" {
		opts.Format = report.FormatHTML
	}
	ext := string(opts.Format)
	switch opts.Format {
	case report.FormatMarkdown:
		ext = "md"
	}
	validScanID := regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	if !validScanID.MatchString(opts.ScanID) {
		return fmt.Errorf("invalid scan id for export: %q", opts.ScanID)
	}
	filename := fmt.Sprintf("akca-report-%s.%s", opts.ScanID, ext)

	dataDir, err := e.GetDataDirectory()
	if err != nil {
		return err
	}
	exportDir := filepath.Join(dataDir, "exports")
	if err := os.MkdirAll(exportDir, 0o755); err != nil {
		return err
	}
	outPath := filepath.Join(exportDir, filename)
	rel, relErr := filepath.Rel(exportDir, outPath)
	if relErr != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return fmt.Errorf("invalid export report path: %q", outPath)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	if err := e.generateReportToWriter(f, opts); err != nil {
		f.Close()
		_ = os.Remove(outPath)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	st, err := os.Stat(outPath)
	if err != nil {
		return err
	}
	return e.Emit("query_result", "report exported", map[string]interface{}{
		"request_id": input.RequestID,
		"query":      input.Query,
		"data": map[string]interface{}{
			"file_path":          outPath,
			"format":             string(opts.Format),
			"template":           string(opts.Template),
			"suggested_filename": filename,
			"size_bytes":         st.Size(),
		},
	})
}

func (e *Engine) generateReportQuery(input CommandInput, params map[string]interface{}) error {
	sess := e.currentSession()
	opts := report.Options{
		ScanID:      sess.ID,
		Template:    report.TemplateKind(strParam(params, "template")),
		Format:      report.Format(strParam(params, "format")),
		Partial:     boolParam(params, "partial"),
		Redact:      false,
		Severities:  strSlice(params, "severities"),
		Confidences: strSlice(params, "confidences"),
	}
	if opts.ScanID == "" {
		opts.ScanID = sess.Config.ScanID
	}
	if opts.Template == "" {
		opts.Template = report.TemplateInternal
	}
	if opts.Format == "" {
		opts.Format = report.FormatJSON
	}
	if _, err := e.GenerateReport(opts); err != nil {
		return err
	}
	return e.Emit("query_result", "report generated", map[string]interface{}{
		"request_id": input.RequestID,
		"query":      input.Query,
		"data":       map[string]interface{}{"status": "ok", "format": opts.Format, "template": opts.Template},
	})
}

func strParam(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func boolParam(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func intParam(m map[string]interface{}, key string, def int) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return def
	}
}

// ValidatedLimit returns a limit parameter clamped to a safe range [1, maxLimit].
// Returns def if the parameter is invalid or outside the allowed range.
func ValidatedLimit(m map[string]interface{}, key string, def, maxLimit int) int {
	limit := intParam(m, key, def)
	if limit <= 0 || limit > maxLimit {
		return def
	}
	return limit
}

func int64Param(m map[string]interface{}, key string, def int64) int64 {
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	default:
		return def
	}
}

func strSlice(m map[string]interface{}, key string) []string {
	raw, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func mapString(m map[string]interface{}, key string) map[string]string {
	raw, ok := m[key].(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
