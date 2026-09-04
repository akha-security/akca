package storage

type Migration struct {
	Version     int
	Description string
	Up          string
	Down        string
}

func sortedMigrations() []Migration {
	m := allMigrations()
	sortMigrations(m)
	return m
}

func sortMigrations(m []Migration) {
	for i := 0; i < len(m); i++ {
		for j := i + 1; j < len(m); j++ {
			if m[j].Version < m[i].Version {
				m[i], m[j] = m[j], m[i]
			}
		}
	}
}

const migration005Up = `
CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id ON endpoints(scan_id);
`

const migration005Down = `
DROP INDEX IF EXISTS idx_endpoints_scan_id;
`

// Migration 6 removes the retired reconnaissance storage from existing
// installations. Fresh databases never create this table in migration 1.
const migration006Up = `
DROP TABLE IF EXISTS subdomain_results;
`

const migration006Down = `
SELECT 1;
`

const migration007Up = `
ALTER TABLE findings ADD COLUMN confidence_score REAL;
`

const migration007Down = `
ALTER TABLE findings DROP COLUMN confidence_score;
`

const migration008Up = `
CREATE TABLE IF NOT EXISTS verification_observations (
  id TEXT PRIMARY KEY,
  finding_id INTEGER,
  scan_id TEXT NOT NULL,
  module TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  parameter TEXT,
  location TEXT,
  role TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  identity_id TEXT,
  request_id TEXT,
  request_method TEXT,
  request_url TEXT,
  request_hash TEXT,
  response_hash TEXT,
  normalized_hash TEXT,
  status_code INTEGER,
  content_type TEXT,
  duration_ms INTEGER,
  state_before_hash TEXT,
  state_after_hash TEXT,
  oast_payload_id TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(finding_id) REFERENCES findings(id),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_verification_observations_scan
  ON verification_observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_verification_observations_finding
  ON verification_observations(finding_id);
CREATE INDEX IF NOT EXISTS idx_verification_observations_proof
  ON verification_observations(scan_id, module, endpoint_url, parameter, role);
`

const migration008Down = `
DROP INDEX IF EXISTS idx_verification_observations_proof;
DROP INDEX IF EXISTS idx_verification_observations_finding;
DROP INDEX IF EXISTS idx_verification_observations_scan;
DROP TABLE IF EXISTS verification_observations;
`

const migration009Up = `
CREATE TABLE IF NOT EXISTS application_states (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  url TEXT NOT NULL,
  dom_fingerprint TEXT NOT NULL,
  auth_identity TEXT NOT NULL,
  storage_hash TEXT,
  actions_json TEXT,
  forms_json TEXT,
  api_calls_json TEXT,
  websocket_json TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS state_transitions (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  from_state_id TEXT,
  to_state_id TEXT NOT NULL,
  action TEXT NOT NULL,
  request_template_json TEXT,
  preconditions_json TEXT,
  side_effects_json TEXT,
  reversible INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(id),
  FOREIGN KEY(from_state_id) REFERENCES application_states(id),
  FOREIGN KEY(to_state_id) REFERENCES application_states(id)
);
CREATE INDEX IF NOT EXISTS idx_application_states_scan ON application_states(scan_id);
CREATE INDEX IF NOT EXISTS idx_state_transitions_scan ON state_transitions(scan_id);
`

const migration009Down = `
DROP INDEX IF EXISTS idx_state_transitions_scan;
DROP INDEX IF EXISTS idx_application_states_scan;
DROP TABLE IF EXISTS state_transitions;
DROP TABLE IF EXISTS application_states;
`

const migration010Up = `
ALTER TABLE verification_observations ADD COLUMN runtime_trace_id TEXT;
ALTER TABLE verification_observations ADD COLUMN runtime_sink TEXT;
ALTER TABLE verification_observations ADD COLUMN runtime_safe INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS runtime_traces (
  trace_id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  candidate_id TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  parameter TEXT,
  verdict TEXT NOT NULL,
  trace_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_traces_request_candidate
  ON runtime_traces(scan_id, request_id, candidate_id);
`

const migration010Down = `
DROP INDEX IF EXISTS idx_runtime_traces_request_candidate;
DROP TABLE IF EXISTS runtime_traces;
ALTER TABLE verification_observations DROP COLUMN runtime_safe;
ALTER TABLE verification_observations DROP COLUMN runtime_sink;
ALTER TABLE verification_observations DROP COLUMN runtime_trace_id;
`

const migration011Up = `
CREATE TABLE IF NOT EXISTS endpoint_observation_sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  url TEXT NOT NULL,
  method TEXT NOT NULL,
  source TEXT NOT NULL,
  observed_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id),
  UNIQUE(scan_id, url, method, source)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_observation_sources_scan
  ON endpoint_observation_sources(scan_id);
CREATE TABLE IF NOT EXISTS shadow_api_diffs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  documented_method TEXT,
  observed_method TEXT,
  source TEXT,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_shadow_api_diffs_scan
  ON shadow_api_diffs(scan_id, kind);
`

const migration011Down = `
DROP INDEX IF EXISTS idx_shadow_api_diffs_scan;
DROP TABLE IF EXISTS shadow_api_diffs;
DROP INDEX IF EXISTS idx_endpoint_observation_sources_scan;
DROP TABLE IF EXISTS endpoint_observation_sources;
`

const migration012Up = `
ALTER TABLE application_states ADD COLUMN service_workers_json TEXT;
ALTER TABLE application_states ADD COLUMN dom_sink_events_json TEXT;
`

const migration012Down = `
ALTER TABLE application_states DROP COLUMN dom_sink_events_json;
ALTER TABLE application_states DROP COLUMN service_workers_json;
`

const migration013Up = `
ALTER TABLE oast_callbacks ADD COLUMN correlation_token TEXT;
ALTER TABLE oast_callbacks ADD COLUMN protocol_strength INTEGER NOT NULL DEFAULT 0;
UPDATE oast_callbacks
SET correlation_token = json_extract(callback_json, '$.correlation.correlation_token'),
    protocol_strength = COALESCE(json_extract(callback_json, '$.protocol_strength'), 0);
DELETE FROM oast_callbacks
WHERE COALESCE(correlation_token, '') <> ''
  AND id NOT IN (
    SELECT MAX(id) FROM oast_callbacks
    WHERE COALESCE(correlation_token, '') <> ''
    GROUP BY scan_id, correlation_token
  );
CREATE UNIQUE INDEX IF NOT EXISTS idx_oast_callbacks_scan_token
  ON oast_callbacks(scan_id, correlation_token)
  WHERE correlation_token IS NOT NULL AND correlation_token <> '';
`

const migration013Down = `
DROP INDEX IF EXISTS idx_oast_callbacks_scan_token;
ALTER TABLE oast_callbacks DROP COLUMN protocol_strength;
ALTER TABLE oast_callbacks DROP COLUMN correlation_token;
`

const migration014Up = `
CREATE TABLE IF NOT EXISTS pack_artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pack_type TEXT NOT NULL,
  channel TEXT NOT NULL,
  version TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  payload TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 0,
  installed_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(pack_type, channel, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pack_artifacts_active
  ON pack_artifacts(pack_type, channel) WHERE active = 1;

CREATE TABLE IF NOT EXISTS distributed_jobs (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  job_type TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  rate_limit_rps REAL NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  owner_id TEXT,
  lease_until TEXT,
  checkpoint_json TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_distributed_jobs_dispatch
  ON distributed_jobs(status, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_distributed_jobs_scan
  ON distributed_jobs(scan_id, status);
`

const migration014Down = `
DROP INDEX IF EXISTS idx_distributed_jobs_scan;
DROP INDEX IF EXISTS idx_distributed_jobs_dispatch;
DROP TABLE IF EXISTS distributed_jobs;
DROP INDEX IF EXISTS idx_pack_artifacts_active;
DROP TABLE IF EXISTS pack_artifacts;
`

const migration015Up = `
CREATE TABLE IF NOT EXISTS policy_evaluations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  current_scan_id TEXT NOT NULL,
  previous_scan_id TEXT,
  passed INTEGER NOT NULL,
  evaluation_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(current_scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_current
  ON policy_evaluations(current_scan_id, created_at);
`

const migration015Down = `
DROP INDEX IF EXISTS idx_policy_evaluations_current;
DROP TABLE IF EXISTS policy_evaluations;
`

func allMigrations() []Migration {
	return []Migration{
		{
			Version:     1,
			Description: "initial schema",
			Up:          migration001Up,
			Down:        migration001Down,
		},
		{
			Version:     2,
			Description: "endpoint discovery trail columns",
			Up:          migration002Up,
			Down:        migration002Down,
		},
		{
			Version:     3,
			Description: "evidence query indexes and findings FTS",
			Up:          migration003Up,
			Down:        migration003Down,
		},
		{
			Version:     4,
			Description: "deduplicate parameters and add unique index",
			Up:          migration004Up,
			Down:        migration004Down,
		},
		{
			Version:     5,
			Description: "endpoints scan_id index for large-scope pagination",
			Up:          migration005Up,
			Down:        migration005Down,
		},
		{
			Version:     6,
			Description: "remove retired domain-enumeration storage",
			Up:          migration006Up,
			Down:        migration006Down,
		},
		{
			Version:     7,
			Description: "persist exact finding confidence score",
			Up:          migration007Up,
			Down:        migration007Down,
		},
		{
			Version:     8,
			Description: "typed verification observation ledger",
			Up:          migration008Up,
			Down:        migration008Down,
		},
		{
			Version:     9,
			Description: "stateful application graph",
			Up:          migration009Up,
			Down:        migration009Down,
		},
		{
			Version:     10,
			Description: "runtime sensor trace correlation",
			Up:          migration010Up,
			Down:        migration010Down,
		},
		{
			Version:     11,
			Description: "shadow API observation and drift inventory",
			Up:          migration011Up,
			Down:        migration011Down,
		},
		{
			Version:     12,
			Description: "persist instrumented browser service worker and DOM sink state",
			Up:          migration012Up,
			Down:        migration012Down,
		},
		{
			Version:     13,
			Description: "strict OAST callback correlation and protocol evidence ranking",
			Up:          migration013Up,
			Down:        migration013Down,
		},
		{
			Version:     14,
			Description: "offline pack artifacts and durable distributed jobs",
			Up:          migration014Up,
			Down:        migration014Down,
		},
		{
			Version:     15,
			Description: "persist proof-aware trend and policy evaluations",
			Up:          migration015Up,
			Down:        migration015Down,
		},
		{
			Version:     16,
			Description: "persist second-order injection markers",
			Up:          migration016Up,
			Down:        migration016Down,
		},
	}
}

const migration016Up = `
CREATE TABLE IF NOT EXISTS second_order_markers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  parameter TEXT NOT NULL,
  marker TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_second_order_markers_scan
  ON second_order_markers(scan_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_second_order_markers_unique
  ON second_order_markers(scan_id, endpoint_url, parameter, marker);
`

const migration016Down = `
DROP INDEX IF EXISTS idx_second_order_markers_unique;
DROP INDEX IF EXISTS idx_second_order_markers_scan;
DROP TABLE IF EXISTS second_order_markers;
`

const migration004Up = `
DELETE FROM parameters
WHERE id NOT IN (
  SELECT MIN(id) FROM parameters GROUP BY endpoint_id, name, location
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_parameters_endpoint_name_location
  ON parameters(endpoint_id, name, location);
`

const migration004Down = `
DROP INDEX IF EXISTS idx_parameters_endpoint_name_location;
`

const migration002Up = `
ALTER TABLE endpoints ADD COLUMN discovery_source TEXT;
ALTER TABLE endpoints ADD COLUMN discovery_confidence REAL;
ALTER TABLE endpoints ADD COLUMN discovery_trail_json TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_scan_norm_method ON endpoints(scan_id, normalized_url, method);
`

const migration002Down = `
DROP INDEX IF EXISTS idx_endpoints_scan_norm_method;
`

const migration003Up = `
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_scan_confidence ON findings(scan_id, confidence);
CREATE INDEX IF NOT EXISTS idx_findings_scan_vuln_class ON findings(scan_id, vuln_class);
CREATE INDEX IF NOT EXISTS idx_findings_scan_endpoint ON findings(scan_id, endpoint_url);
CREATE INDEX IF NOT EXISTS idx_evidence_scan_id ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_request_records_scan_id ON request_records(scan_id);
CREATE INDEX IF NOT EXISTS idx_response_records_request_id ON response_records(request_id);
CREATE INDEX IF NOT EXISTS idx_fuzz_results_scan_id ON fuzz_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_oast_callbacks_scan_id ON oast_callbacks(scan_id);
CREATE INDEX IF NOT EXISTS idx_finding_groups_scan_id ON finding_groups(scan_id);
CREATE INDEX IF NOT EXISTS idx_root_cause_clusters_scan_id ON root_cause_clusters(scan_id);
CREATE INDEX IF NOT EXISTS idx_payload_outcome_scan_id ON payload_outcome_history(scan_id);
CREATE INDEX IF NOT EXISTS idx_api_key_validation_scan_id ON api_key_validation_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_waf_profiles_scan_id ON waf_profiles(scan_id);
CREATE INDEX IF NOT EXISTS idx_tech_fingerprints_scan_id ON tech_fingerprints(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_checkpoints_scan_id ON scan_checkpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_resume_state_scan_id ON resume_state(scan_id);
CREATE INDEX IF NOT EXISTS idx_health_snapshots_scan_id ON health_snapshots(scan_id);

CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
  title, summary, description, evidence_json,
  content='findings', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS findings_fts_insert AFTER INSERT ON findings BEGIN
  INSERT INTO findings_fts(rowid, title, summary, description, evidence_json)
  VALUES (new.id, new.title, COALESCE(new.summary,''), COALESCE(new.description,''), COALESCE(new.evidence_json,''));
END;

CREATE TRIGGER IF NOT EXISTS findings_fts_delete AFTER DELETE ON findings BEGIN
  INSERT INTO findings_fts(findings_fts, rowid, title, summary, description, evidence_json)
  VALUES ('delete', old.id, old.title, COALESCE(old.summary,''), COALESCE(old.description,''), COALESCE(old.evidence_json,''));
END;

CREATE TRIGGER IF NOT EXISTS findings_fts_update AFTER UPDATE ON findings BEGIN
  INSERT INTO findings_fts(findings_fts, rowid, title, summary, description, evidence_json)
  VALUES ('delete', old.id, old.title, COALESCE(old.summary,''), COALESCE(old.description,''), COALESCE(old.evidence_json,''));
  INSERT INTO findings_fts(rowid, title, summary, description, evidence_json)
  VALUES (new.id, new.title, COALESCE(new.summary,''), COALESCE(new.description,''), COALESCE(new.evidence_json,''));
END;
`

const migration003Down = `
DROP TRIGGER IF EXISTS findings_fts_update;
DROP TRIGGER IF EXISTS findings_fts_delete;
DROP TRIGGER IF EXISTS findings_fts_insert;
DROP TABLE IF EXISTS findings_fts;
DROP INDEX IF EXISTS idx_health_snapshots_scan_id;
DROP INDEX IF EXISTS idx_resume_state_scan_id;
DROP INDEX IF EXISTS idx_scan_checkpoints_scan_id;
DROP INDEX IF EXISTS idx_tech_fingerprints_scan_id;
DROP INDEX IF EXISTS idx_waf_profiles_scan_id;
DROP INDEX IF EXISTS idx_api_key_validation_scan_id;
DROP INDEX IF EXISTS idx_payload_outcome_scan_id;
DROP INDEX IF EXISTS idx_root_cause_clusters_scan_id;
DROP INDEX IF EXISTS idx_finding_groups_scan_id;
DROP INDEX IF EXISTS idx_oast_callbacks_scan_id;
DROP INDEX IF EXISTS idx_fuzz_results_scan_id;
DROP INDEX IF EXISTS idx_response_records_request_id;
DROP INDEX IF EXISTS idx_request_records_scan_id;
DROP INDEX IF EXISTS idx_evidence_finding_id;
DROP INDEX IF EXISTS idx_evidence_scan_id;
DROP INDEX IF EXISTS idx_findings_scan_endpoint;
DROP INDEX IF EXISTS idx_findings_scan_vuln_class;
DROP INDEX IF EXISTS idx_findings_scan_confidence;
DROP INDEX IF EXISTS idx_findings_scan_severity;
DROP INDEX IF EXISTS idx_findings_scan_id;
`

const migration001Up = `
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  app_name TEXT,
  status TEXT NOT NULL,
  config_json TEXT NOT NULL,
  requests_sent INTEGER DEFAULT 0,
  started_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  url TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS scope_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  rule_type TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  url TEXT NOT NULL,
  method TEXT NOT NULL,
  normalized_url TEXT NOT NULL,
  discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS endpoint_intelligence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint_id INTEGER NOT NULL,
  endpoint_type TEXT,
  auth_required INTEGER NOT NULL DEFAULT 0,
  state_changing INTEGER NOT NULL DEFAULT 0,
  content_type TEXT,
  risk_tags_json TEXT,
  recommended_modules_json TEXT,
  FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);

CREATE TABLE IF NOT EXISTS parameters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);

CREATE TABLE IF NOT EXISTS request_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  endpoint_id INTEGER,
  method TEXT NOT NULL,
  url TEXT NOT NULL,
  headers_json TEXT,
  body TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS response_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id INTEGER NOT NULL,
  status_code INTEGER NOT NULL,
  headers_json TEXT,
  body TEXT,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(request_id) REFERENCES request_records(id)
);

CREATE TABLE IF NOT EXISTS waf_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  host TEXT NOT NULL,
  vendor TEXT,
  profile_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS tech_fingerprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  host TEXT NOT NULL,
  fingerprint_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS fuzz_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  url TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  category TEXT,
  result_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS oast_callbacks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  payload_id TEXT NOT NULL,
  protocol TEXT,
  source_ip TEXT,
  callback_json TEXT NOT NULL,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT,
  description TEXT,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  vuln_class TEXT NOT NULL,
  endpoint_url TEXT,
  parameter TEXT,
  evidence_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS finding_groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  root_cause TEXT NOT NULL,
  group_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS root_cause_clusters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  cluster_key TEXT NOT NULL,
  cluster_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER,
  scan_id TEXT NOT NULL,
  evidence_type TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(finding_id) REFERENCES findings(id),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  template TEXT NOT NULL,
  format TEXT NOT NULL,
  path TEXT,
  report_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT,
  level TEXT NOT NULL,
  message TEXT NOT NULL,
  context_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS payload_outcome_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  outcome TEXT NOT NULL,
  details_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS auth_profiles (
  id TEXT PRIMARY KEY,
  scan_id TEXT,
  name TEXT NOT NULL,
  profile_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS role_profiles (
  id TEXT PRIMARY KEY,
  scan_id TEXT,
  name TEXT NOT NULL,
  auth_profile_id TEXT,
  profile_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS encrypted_secret_refs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT,
  secret_key TEXT NOT NULL,
  storage_mode TEXT NOT NULL,
  ref_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_checkpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  checkpoint_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS resume_state (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  state_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS health_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT,
  metrics_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS baseline_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  method TEXT NOT NULL,
  baseline_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS error_fingerprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  fingerprint_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS rule_pack_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel TEXT NOT NULL,
  version TEXT NOT NULL,
  metadata_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS payload_pack_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel TEXT NOT NULL,
  version TEXT NOT NULL,
  metadata_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS browser_worker_health (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  worker_id TEXT NOT NULL,
  status TEXT NOT NULL,
  health_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS benchmark_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scenario TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS learning_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  endpoint_url TEXT,
  profile_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS waf_learning_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  profile_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS waf_bypass_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  strategy_id TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS cve_catalog (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  catalog_json TEXT NOT NULL,
  snapshot_version TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS component_inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  component_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS component_cve_matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  component_id INTEGER NOT NULL,
  cve_id TEXT NOT NULL,
  match_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(component_id) REFERENCES component_inventory(id)
);

CREATE TABLE IF NOT EXISTS user_finding_annotations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER NOT NULL,
  annotation_type TEXT NOT NULL,
  notes TEXT,
  annotated_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(finding_id) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS scheduled_scans (
  id TEXT PRIMARY KEY,
  cron_expression TEXT NOT NULL,
  config_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  next_run_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scheduled_scan_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schedule_id TEXT NOT NULL,
  scan_id TEXT,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT,
  FOREIGN KEY(schedule_id) REFERENCES scheduled_scans(id)
);

CREATE TABLE IF NOT EXISTS comparison_scan_diffs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  previous_scan_id TEXT NOT NULL,
  current_scan_id TEXT NOT NULL,
  diff_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS proxy_intercept_sessions (
  id TEXT PRIMARY KEY,
  session_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS proxy_traffic_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  traffic_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(session_id) REFERENCES proxy_intercept_sessions(id)
);

CREATE TABLE IF NOT EXISTS command_center_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT,
  request_json TEXT NOT NULL,
  response_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS payload_library_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_key_validation_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT,
  service TEXT NOT NULL,
  status TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS keyboard_shortcuts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action_id TEXT NOT NULL,
  default_binding TEXT NOT NULL,
  custom_binding TEXT,
  category TEXT,
  description TEXT,
  is_global INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS timeline_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  summary TEXT NOT NULL,
  event_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  workspace_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS team_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL,
  member_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);

CREATE TABLE IF NOT EXISTS workspace_invitations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL,
  invitation_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);

CREATE TABLE IF NOT EXISTS audit_log_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT,
  entry_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS shared_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL,
  finding_id INTEGER NOT NULL,
  share_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(id),
  FOREIGN KEY(finding_id) REFERENCES findings(id)
);
`

const migration001Down = `
DROP TABLE IF EXISTS shared_findings;
DROP TABLE IF EXISTS audit_log_entries;
DROP TABLE IF EXISTS workspace_invitations;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS workspaces;
DROP TABLE IF EXISTS timeline_events;
DROP TABLE IF EXISTS keyboard_shortcuts;
DROP TABLE IF EXISTS api_key_validation_results;
DROP TABLE IF EXISTS payload_library_items;
DROP TABLE IF EXISTS command_center_requests;
DROP TABLE IF EXISTS proxy_traffic_records;
DROP TABLE IF EXISTS proxy_intercept_sessions;
DROP TABLE IF EXISTS comparison_scan_diffs;
DROP TABLE IF EXISTS scheduled_scan_runs;
DROP TABLE IF EXISTS scheduled_scans;
DROP TABLE IF EXISTS user_finding_annotations;
DROP TABLE IF EXISTS component_cve_matches;
DROP TABLE IF EXISTS component_inventory;
DROP TABLE IF EXISTS cve_catalog;
DROP TABLE IF EXISTS waf_bypass_results;
DROP TABLE IF EXISTS waf_learning_profiles;
DROP TABLE IF EXISTS learning_profiles;
DROP TABLE IF EXISTS benchmark_results;
DROP TABLE IF EXISTS browser_worker_health;
DROP TABLE IF EXISTS payload_pack_versions;
DROP TABLE IF EXISTS rule_pack_versions;
DROP TABLE IF EXISTS error_fingerprints;
DROP TABLE IF EXISTS baseline_profiles;
DROP TABLE IF EXISTS health_snapshots;
DROP TABLE IF EXISTS resume_state;
DROP TABLE IF EXISTS scan_checkpoints;
DROP TABLE IF EXISTS encrypted_secret_refs;
DROP TABLE IF EXISTS role_profiles;
DROP TABLE IF EXISTS auth_profiles;
DROP TABLE IF EXISTS payload_outcome_history;
DROP TABLE IF EXISTS logs;
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS root_cause_clusters;
DROP TABLE IF EXISTS finding_groups;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS oast_callbacks;
DROP TABLE IF EXISTS fuzz_results;
DROP TABLE IF EXISTS tech_fingerprints;
DROP TABLE IF EXISTS waf_profiles;
DROP TABLE IF EXISTS response_records;
DROP TABLE IF EXISTS request_records;
DROP TABLE IF EXISTS parameters;
DROP TABLE IF EXISTS endpoint_intelligence;
DROP TABLE IF EXISTS endpoints;
DROP TABLE IF EXISTS scope_rules;
DROP TABLE IF EXISTS targets;
DROP TABLE IF EXISTS scans;
`
