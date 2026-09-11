# Changelog

All notable changes to AKCA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

## [0.1.9] - 2026-09-11

### Fixed

- Reduce false positives in CORS, open redirects, CSTI, JSONP, WebSocket, prototype pollution, parser differential and route authentication checks by requiring evidence of the claimed security effect.
- Validate actual redirect destinations instead of attacker URLs embedded in nested query parameters.
- Repair stored-XSS tracking and raw HTTP smuggling verification; preserve raw request and response evidence.
- Include response status and security-relevant headers in finding replay comparisons.
- Correct coverage accounting, persistent learning outcome counts, response similarity and cache-hit detection.
- Share request budgets across HTTP, browser HTTP and raw protocol probe paths.
- Restore Copy Response, Copy Request and Copy cURL in HTML reports, including a clipboard fallback.
- Isolate the CLI integration test from the user's data directory.

### Added

- Private-canary proof policies and browser cross-origin read observations.
- Regression tests for the reported false positives, raw protocol replay, clipboard behavior and shared budgets.
- Audit and validation reports documenting remaining verification limits.

### Validation

- The preceding changes passed tests in 80 Go packages and `go vet`.
- The strict observed benchmark passed for the existing corpus.
- Live third-party/browser coverage is not inferred from fixture tests; local race testing required an unavailable GCC toolchain.

## [0.1.8] - 2026-09-08

### Added

- **Physical Wire Transport & Budget Enforcement**:
  - Implemented `WireTransport` interceptor that accurately captures every physical outbound network transaction, including redirect hops and transport-level retries.
  - Enforced strict global `RequestBudget` on physical wire requests, guaranteeing scans strictly respect user-defined traffic boundaries even during redirection chains.
  - Enforced per-host rate limiting directly at the wire level.
- **Enhanced Redirect Security & Sensitive Header Stripping**:
  - Automatically strip authentication and session headers (`Authorization`, `Cookie`, `Proxy-Authorization`, `X-API-Key`, `X-Auth-Token`, `X-Token`, `Session-Token`, `API-Key`, `Private-Token`, `Token`) on cross-origin redirects.
  - Enforced credential stripping on HTTPS to HTTP protocol downgrades even on the same host.
  - Enforced credential stripping on cross-port redirects.
- **Timing-Differential Blind NoSQL Injection Verification**:
  - Integrated timing-based blind NoSQL injection verification (`where_sleep`, `$where` JavaScript sleep) alongside differential replay.
  - Added baseline timing calibration and zero-delay controls (`sleep(0)`) to eliminate false positives in time-based NoSQL attacks.
  - Added delayed verification scheduling support for NoSQL timing attacks.
  - Expanded MongoDB error detection signatures with `mongoStrongErrorMarkers` to catch syntax and query evaluation exceptions reliably.
- **Multipart & XML Native Parameter Discovery**:
  - Extended native body mutation engine (`mutateNativeBody`) to support `application/xml` and `multipart/form-data` request templates.
  - Automatic boundary management and field insertion for multipart body fuzzing.
  - Support for `multipart/form-data` and `application/json` form encodings (`enctype`) in crawler form extraction.

### Fixed & Hardened

- **SQL Injection Engine & Status Code Tolerance**:
  - Expanded SQLi strong error keywords to capture syntax errors, unclosed quotes, and terminated statement messages across major database engines.
  - Relaxed strict status code matching in timing-based SQLi probes (`acceptableTimingStatusPair`) to prevent valid delay findings from being dropped when the server returns expected error statuses (e.g. 500) on delayed syntax.
- **Crawler Bounding & Scope Protection**:
  - Restricted crawler per-route template saturation (`maxURLsPerRouteTemplate = 30`) to avoid combinatorial explosion on large REST APIs.
  - Enforced strict redirect domain adoption: by default only canonical apex/www pairs (e.g. `example.com` <-> `www.example.com`) are automatically adopted into scope; wider subdomain adoption requires explicit configuration (`cfg.AutoAdoptSameRootRedirects`).
  - Pre-compiled text URL regex (`reTextURL`) for improved extraction throughput.
- **Reflection Analyzer & XSS Sentinels**:
  - Corrected character sentinel probe definitions and close tags (`CK>DK`, `QK}RK`), with dynamic sentinel payload assembly and regression test coverage.
- **Platform Telemetry & Scan Management**:
  - Upgraded Command Center / Health Metrics UI (`HealthMetricsUI`) to report live system stats (active goroutines from `runtime.NumGoroutine()`, allocated memory from `runtime.ReadMemStats()`, and real database write latency).
  - Enhanced scan comparison engine to list all findings using streaming iteration and improved deduplication key (`VulnClass|EndpointURL|Parameter|Title`).
  - Enhanced scan initialization to ensure scan records and configuration are properly persisted in the database before starting scan session.
  - Improved scan ID generation (`deriveTargetScanID`) with target hashing and nanosecond uniqueness to prevent scan ID collisions.
  - Hardened report builder error handling and added `Warnings` array to report `Document`.

## [0.1.7] - 2026-09-07

### Added

- **Arjun-Style GET-to-POST Method Pivoting & Hidden Parameter Discovery**:
  - Automatic probing on GET endpoints to test if they accept POST requests without 405/404/501 rejections.
  - Dual-surface differential probing: simultaneously fuzzes URL query parameters and JSON/Form request bodies.
  - Automatic promotion: discovered hidden POST parameters automatically register new `POST` endpoints in the database, allowing vulnerability modules (SQLi, IDOR, SSRF, Mass Assignment) to target them.
- **Surface-Adaptive Per-Module Granular Budgeting**:
  - Replaced blunt global request budget cutoff with surface-proportional allocations scaled by discovered target counts (`len(targets)`).
  - Granular probe quotas per vulnerability type: SQLi/NoSQL (24), XSS (20), RCE/SSTI (16), SSRF/XXE (12), IDOR/Auth (10), CORS/CRLF (6).
  - Strict module isolation prevents heavy modules from starving subsequent checks.
- **High-Impact Parameter Wordlist & Context-Aware Prioritization**:
  - Expanded parameter dictionary with top bug bounty parameters across SSRF/Proxy (`dest`, `target_url`, `proxy`, `remote`), Cloud/AWS (`bucket`, `s3_key`, `role_arn`), Privilege Escalation (`admin`, `is_admin`, `sudo`, `impersonate`, `bypass`), File Inclusion (`template_path`, `view_path`), and Prototype Pollution (`__proto__`, `constructor`).
  - Context-aware prioritization dynamically pulls admin, cloud, upload, and proxy parameters to the front based on URL path semantics.

### Fixed & Hardened

- **Core Engine & HTTP Client Stability**:
  - Eliminated redundant `UpdateScanFinished("running")` call that overwrote final completion status in database.
  - Fixed nil pointer dereference panic in `runMetricsLoop` when platform health is uninitialized.
  - Fixed request budget counter incrementing inside retry loops, eliminating 3x budget burn on transient network retries.
  - Upgraded WAF bypass headers to use cryptographically secure random IP generation (`crypto/rand`).
  - Corrected rate limiter jitter calculation to be zero-centered (`±5%`), preventing negative interval drift.
  - Fixed HTTP 429 response body handling to preserve evidence without retrying, while recording `Retry-After` cooldowns for future requests.
  - Extended preflight status checks to cover all HTTP 5xx codes (502, 503, 504, 500+).
  - Restricted scope auto-expansion prefixes to strictly API/service endpoints, avoiding dev/staging scope creep.
  - Resolved non-standard port scope matching in `deriveIncludeDomains`.
  - Replaced hardcoded proxy intercept port with dynamic port allocation (`127.0.0.1:0`).
  - Fixed rune boundary truncation in repeater preventing broken multi-byte UTF-8 characters.

### Optimized & CLI Polish

- **Target-Level TLS Misconfiguration Scoping**:
  - Anchored TLS inspections strictly to the root domain (`https://host/`), preventing confusing findings on subpages such as `.env` with misleading HTTP 200 statuses.
- **CLI Output Hygiene**:
  - Silenced repetitive `[COVERAGE] Stateful proof coverage requires an explicit reversible policy` notices in normal mode, reserving them exclusively for `--verbose`.
  - Fixed `SCAN SESSION` panel rendering: replaced dim/grey vertical borders and dividers with uniform, vibrant lavender/blue styling.
- **API Versioning Scan Speed**:
  - Restricted `api_versioning` to run once per host on root or base API endpoints, eliminating thousands of redundant subpage probes and reducing module runtime from minutes to seconds.

## [0.1.6] - 2026-09-06

### Added

- **Universal Type-Aware Probing Across All Modules**:
  - **SQL Injection**: Added automatic numeric boolean and error-based probes (`AND 1=CONVERT(...)`, `CAST(...)`, `EXTRACTVALUE(...)`, `subzero -0`) for numeric parameters, prioritized database-hinted payloads (PostgreSQL, MSSQL, MySQL, Oracle, SQLite) within initial probe sequences, and prioritized numeric boolean pairs in boolean-blind verification.
  - **Command Injection**: Prepending numeric-prefixed injection probes (`1; id`, `1|id`, `1&&id`, `1$(id)`) and numeric canary evaluations for integer/numeric parameters to bypass strict prefix input validation.
  - **NoSQL Injection**: Implemented nested dotted path resolution (`user.account.name`) across MongoDB operator queries (`$ne`, `$gt`, `$regex`, `$or`) and authentication bypass bodies.
  - **IDOR / BOLA**: Enhanced parameter detection with `nativeTargetValue` across JSON, form, query, and path locations; added type-aware increment/decrement (`+1`, `-1`, `+2`) and UUID character mutations.
  - **LFI / Path Traversal**: Balanced Linux and Windows traversal testing with increased thresholds to prevent premature fast-fail on cross-platform targets.

- **Adaptive Fair-Share Budgeting & Dynamic Rollover**:
  - Added category-weighted budget partitioning (Injection 35%, Server-Side 25%, Logic & Auth 25%, Client & Exposure 15%) when `--request-budget` is set, eliminating starvation where early modules consume all requests and starve later modules.
  - Implemented dynamic budget rollover: unspent requests from completed modules and groups are automatically returned to a shared reserve pool for subsequent modules to utilize.
  - Added explicit coverage gap metrics (`targets_tested`, `targets_total`, and `coverage_percentage`) whenever budgets are exhausted, preventing silent false negatives.

### Fixed

- **Nested JSON & Array Mutation Failures**:
  - Rewrote JSON path traversal in `reflection.MutateRequest` and `setJSONPath` to support bracket notation (`users[0].id`), dot notation (`users.0.id`), and unindexed array mutations (`users.id`).
  - Implemented strict schema preservation in `schemaCompatibleJSONValue` preventing container objects and arrays from being overwritten with scalar string payloads.
  - Updated `loader.go:collectJSONKeys` to target only leaf scalar values, preventing 400 Bad Request schema validation rejections on REST/JSON APIs.

## [0.1.5] - 2026-09-06

### Fixed

- **WAF Intelligence & Evasion**:
  - Fixed `MutatePayload` case randomization execution order in `ApplyStrategy` to run prior to encodings, preventing corruption of JS/JSON unicode escape tokens (`\u` -> `\U`).
  - Fixed calibration double-encoding in `wafintel/runner.go` by verifying `IsURLSafePayload` before applying `url.QueryEscape`, ensuring target applications receive intended bypass payloads rather than unparsed quadruple-encoded strings.
- **WAF Rate Limit Throttling Lock (3 RPS)**:
  - Replaced permanent base rate and concurrency reduction (`SetRates` / `ApplyTrafficBudget`) upon WAF challenge/429 with dynamic WAF throttling via `ApplyCautiousMode` (`SetWAFSlowDown`). Scan speed automatically recovers back to configured intensity as requests succeed via `DecayWAFSlowDown`.
- **LiteSpeed Header Signature Matching**:
  - Added prefix-based matching for headers ending with `-` (e.g. `x-ls-` and `x-litespeed-`) so LiteSpeed cache and server headers are accurately classified.
- **Vulnerability Scanner False Positives**:
  - SSRF: Eliminated false positives on path-like payloads (e.g. `/content/http://127.0.0.1/`) returning 404 or reflection without true backend SSRF requests.
  - Web Cache Deception: Verified against false positives on static path appendages (e.g. `;.css`) when no sensitive authenticated session content is exposed or cached.
  - CRLF Injection: Enforced strict HTTP header validation so reflected CRLF body payloads within JSON/HTML/escaped text are no longer flagged as header injection.

### Optimized

- **CORS Scanning Performance**:
  - Resolved 11-hour bottleneck in `vuln_module_cors` via endpoint module deduplication (`endpointModuleOnce`), route pattern normalization (`normalizeRoutePattern`), static asset skipping (`isStaticAssetURL`), smart early-exit on non-CORS endpoints, and single-run host-scoped OAST SSRF probes.

## [0.1.4] - 2026-09-05

### Optimized

- **Headless Browser & Crawler Performance**:
  - Increased default Chromium pool concurrency from 2 to 6 slots (`NewHeadlessRendererWithPoolSize`, `CrawlerBrowser.SetConcurrency`), allowing proper parallel headless rendering matching crawler worker counts.
  - Dynamically configured browser worker pool size based on session configuration (`BrowserWorkerPoolSize` / `MaxConcurrency`).
  - Tuned page settling delay in CDP navigation from 1500ms down to 500ms, removing an unnecessary 1-second idle wait per page.
  - Added script detection guard in crawler: pages without `<script` tags skip headless Chromium rendering entirely, preventing slow browser rendering on purely static HTML responses.
- **Hidden Parameter Discovery Parallelism**:
  - Replaced sequential single-threaded wordlist candidate probing in Phase 1 with a concurrent worker pool (8–10 workers), eliminating the latency bottleneck of probing 64–160+ items sequentially per endpoint.
- **Eliminated Downstream Parameter Target Inflation**:
  - Removed unverified heuristic variant generation (`paramVariants`) from SQLite parameter persistence during differential discovery. Only confirmed parameters are persisted, preventing downstream test amplification in reflection and vulnerability analysis modules.

## [0.1.3] - 2026-09-05

### Fixed

- **Secret Scan False Positives**:
  - Tightened OpenAI API key detection: classic keys (`sk-`) now strictly require alphanumeric base62 strings without hyphens (`sk-[A-Za-z0-9]{32,64}`), and `Detect()` enforces entropy/character diversity filters. Model numbers and kebab-case product slugs (e.g. `sk-8030-device-sku-...`) are no longer flagged.
  - Corrected Okta API token pattern: removed hyphens and underscores (`00[A-Za-z0-9]{40}`) and added entropy and character complexity checks to prevent false alarms on e-commerce slugs (e.g. `000-item-catalog-sku-...`) and repeated zero sequences.
- **API Versioning Redirect False Positives**:
  - HTTP client now records redirect telemetry (`Redirected`, `FinalURL`, `InitialStatus`).
  - `api_versioning` module rejects responses that resulted from 302/3xx redirects to different endpoints (such as `/login` or root `/`) as well as HTML responses (`<html`, `<!doctype`).

### Optimized

- **Reflection Analysis Performance**:
  - Skipped redundant stability reprobe requests (`rr2`) when no canary reflection is observed (`ReflectionRemoved`), cutting HTTP requests by up to ~50% across targets.
  - Implemented concurrent worker pool in `Analyzer.Run()` with configurable concurrency (tied to `MaxConcurrency`), drastically reducing reflection phase execution time.

## [0.1.2] - 2026-09-05

### Added

- **Dynamic Character Pre-flight Matrix**: Calibration phase now probes critical syntactic characters (`'`, `"`, `<`, `;`, `|`) to map blocked characters and dynamically discover successful bypass encodings per WAF.
- **Context-Aware WAF Mutations**: Adapted mutations now respect reflection context (JSON, JavaScript, HTML attributes, XML), preventing parser syntax breakdown and avoiding false negatives.
- **Paired Mutated Negative Controls**: Every WAF-adapted offensive payload is paired with an identically encoded negative control to eliminate false positives caused by unparsed garbage input.
- **Character Block-Aware Payload Ranking**: Payload scoring now rewards encodings that conceal WAF-blocked characters and penalizes unencoded blocked tokens under budget constraints.

## [0.1.1] - 2026-09-05

### Fixed

- Eliminated widespread false positives in `sensitive_files` (`.htpasswd` now requires valid Unix crypt/MD5/SHA/bcrypt hashes; `.dockerenv` rejects 0-byte responses; `docker-compose.yml` requires services definition).
- Tightened `cloud_takeover` signatures for Fly.io, Strikingly, Cargo Collective, and Unbounce to prevent alerting on generic 404 pages.
- Standardized `deeptraversal` tokens to specific Unix/Windows OS files and removed generic keyword matches (`path=`, `heap`, `stack`, `version=`, etc.).
- Fixed false shortname confirmation bug in `fp_guard` (`iis_discovery`) when baseline and probe both return 404.
- Added root URL/SPA baseline comparison in `route_auth_bypass` to prevent alerting when path traversal sequences normalize back to public root.
- Reclassified uncredentialed cloud metadata origin reflection in `cors` from critical SSRF to low severity.
- Reclassified public WebSocket connections in `ws_cswsh` from high severity CSWSH to info when no authenticated user session exists.
- Filtered public contact and role-based mail addresses (`support@`, `info@`, `sales@`, `contact@`) in `sensitivedata` and restricted PII keyword triggers to JSON/API responses.
- Reclassified rate limit threshold discoveries to informative telemetry rather than medium vulnerabilities.
- Added wildcard/SPA catch-all guards in `devops_exposure` and `cloud_native_exposure`, and tightened Docker and Elasticsearch schema verifiers.
- Reduced credit-card false positives with Luhn, issuer/length, context,
  low-diversity and known-test-number validation.
- Reduced IBAN false positives with official country lengths, mod-97 checksum,
  context validation and documentation/fixture rejection.
- Made sensitive-data proof matching specific to both the reported type and value.
- Reduced HTTP request-smuggling scan time by avoiding duplicate route probes,
  caching stable HTTP/1.1 controls, remembering unsupported HTTP/2 ALPN, and
  consuming raw HTTP responses correctly.
- Reduced secret-exposure scan time by treating it as passive content evidence,
  caching detector results for identical bodies, and avoiding redundant replay
  requests.
- Restored CRLF detection coverage for common parameter names and body
  response-splitting evidence.
- Stopped automatically adding linked API/service subdomains to crawl scope by
  default; explicitly included hosts and wildcard scopes still work.

### Added

- GitHub community, contribution and security documentation.
- `go install -v github.com/akha-security/akca/engine/cmd/akca@latest`
  installation instructions.
- `--include-linked-api-subdomains` to opt into the previous broad crawler scope
  expansion for linked API/service subdomains.

## [0.1.0] - 2026-09-04

### Added

- Evidence-driven DAST pipeline with typed proof policies.
- Concurrent HTTP and headless-browser discovery.
- JavaScript, source-map, API and hidden-parameter analysis.
- OpenAPI 3.0/3.1, RAML, Postman, HAR, WSDL, GraphQL, protobuf and AsyncAPI import.
- Injection, authorization, authentication, API, browser, cloud, protocol,
  exposure and business-logic security modules.
- OAST and runtime-sensor correlation.
- SQLite evidence ledger, checkpoints, resume and finding replay.
- HTML, JSON, Markdown, CSV and SARIF reporting.
- CWE and OWASP Top 10:2025 report classification.

[Unreleased]: https://github.com/akha-security/akca/compare/v0.1.9...HEAD
[0.1.9]: https://github.com/akha-security/akca/releases/tag/v0.1.9
[0.1.8]: https://github.com/akha-security/akca/releases/tag/engine/v0.1.8
[0.1.7]: https://github.com/akha-security/akca/releases/tag/v0.1.7
[0.1.6]: https://github.com/akha-security/akca/releases/tag/v0.1.6
[0.1.5]: https://github.com/akha-security/akca/releases/tag/v0.1.5
[0.1.4]: https://github.com/akha-security/akca/releases/tag/v0.1.4
[0.1.3]: https://github.com/akha-security/akca/releases/tag/v0.1.3
[0.1.2]: https://github.com/akha-security/akca/releases/tag/v0.1.2
[0.1.1]: https://github.com/akha-security/akca/releases/tag/v0.1.1
[0.1.0]: https://github.com/akha-security/akca/releases/tag/v0.1.0

