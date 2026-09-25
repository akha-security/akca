# Changelog

All notable changes to AKCA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

## [v0.2.3] - 2026-09-25

### Added

- Add a redesigned HTML security report with an executive risk overview, severity distribution, scan metadata and structured vulnerability statistics.
- Add dedicated finding sections for affected endpoints, impact, classification and remediation guidance.
- Add tabbed HTTP request and response evidence while retaining proof highlighting, cURL reproduction and clipboard controls.
- Add a prominent partial-coverage warning when scan gaps prevent a clean result from representing complete assurance.

### Changed

- Simplify the scan-session card around target, profile, coverage and traffic policy instead of exposing raw internal budget values.
- Refine the live progress row with readable URL counts, professional status text and suppression of meaningless zero-rate output.
- Format large counters and memory limits consistently for terminal readability.
- Document why comprehensive Full Scans take longer and how to request faster, bounded feedback safely.

### Validation

- Full Go package tests pass with `go test ./... -count=1`.
- CLI static analysis passes with `go vet ./cmd/akca`.
- Report regression tests cover the risk dashboard, severity statistics, partial-coverage warning and tabbed HTTP evidence.

## [v0.2.2] - 2026-09-25

### Fixed

- Recursively analyze lazy-loaded JavaScript chunks and retain script dependencies independently from the API-finding confidence threshold.
- Preserve extra login fields, multi-stage authentication requests, cookies and response bearer tokens during automatic login and reauthentication.
- Require typed, replayable evidence for GraphQL, WebSocket, API exposure, JWT and authorization findings instead of promoting generic response differences.
- Redact JavaScript secret values and nested login credentials from diagnostic events and stored scan configuration.

### Added

- Coverage and module-readiness diagnostics in JSON, HTML and Markdown reports, including explicit partial-scan warnings.
- Regression tests for recursive SPA chunk discovery, token-only and multi-step login sessions, report coverage rendering and routine non-applicable module skips.

### Validation

- Full Go package tests, including the controlled local testlab scan, pass with `go test ./... -count=1 -timeout=180s`.
- Static analysis passes with `go vet ./...`.
- The strict observed benchmark passes with precision, recall and specificity of `1.0` and a false-positive rate of `0` on its available corpus.

## [v0.2.1] - 2026-09-23

### Fixed

- Reject SQL injection evidence when baseline or payload responses return HTTP 4xx, preventing bad-request boolean probes such as `1 AND 20909=20909` from being reported as confirmed injection.
- Continue crawler discovery through browser-assisted rendering when initial HTTP requests are blocked or empty, including 403 responses that still load in a normal browser.
- Remove crawler route-saturation caps from unbounded full scans and fix queue-drain accounting so discovery does not end while requests are still being scheduled.
- Initialize adaptive module budgets from the module catalog so every registered full-scan module receives a request plan and usage counter.

### Added

- Coverage-gap reporting for blocked or contentless crawl starts, making `0 crawler requests` style failures visible instead of silently completing.
- Regression tests for blocked-browser crawling, redirect discovery, SQLi 4xx false-positive rejection and catalog-wide module budget initialization.

### Validation

- Full Go package tests pass with `go test ./... -count=1`.
- Static analysis passes with `go vet ./...`.

## [v0.2.0] - 2026-09-12

### Added

- Add adaptive vulnerability-module budgets derived from distinct discovered URL/method surfaces, with weighted module allocation, per-URL reservations and unused-budget rollover.
- Add transport-level budget accounting for redirects, retries and external protocol reservations without double charging normal HTTP requests.
- Add response evidence highlighting for active and passive findings in HTML reports.
- Preserve bounded response excerpts around detected API keys, secrets, JavaScript disclosures, compromised CDN references and third-party scripts missing Subresource Integrity.
- Expand SQL injection coverage with numeric arithmetic contrasts, direct numeric boolean pairs and LIKE-clause variants.

### Fixed

- Prevent early endpoints and parameters from consuming the request shares reserved for later discovered URLs.
- Treat budget-interrupted targets as incomplete and expose coverage gaps in normal CLI output and persistent scan events.
- Remove the normal-profile SQL scout fast-fail so later classic payloads are exercised; retain the optimization for the explicit fast profile.
- Preserve POST body parameters when fallback targets are constructed from endpoint request templates.
- Highlight exact module-specific response values without treating presentation markers as verification proof.

### Validation

- All Go package tests pass with `go test ./... -count=1 -timeout 5m`.
- Static analysis passes with `go vet ./...`.
- Adaptive allocation tests cover single and parallel workers, redirects, retries, cancellation, module rollover and explicit or URL-derived budgets.
- Report tests cover active payloads and passive response excerpts while rejecting unrelated HTML and asset text as evidence markers.

## [v0.1.9] - 2026-09-11

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

## [v0.1.8] - 2026-09-08

### Added

- Physical wire transport interception with strict request budgets across redirects, retries and per-host pacing.
- Timing-based blind NoSQL verification with baseline calibration, zero-delay controls and delayed confirmation.
- Native multipart and XML request mutation, including boundary management and crawler form encoding support.
- Live health metrics, improved scan comparison streaming and collision-resistant scan IDs.

### Fixed

- Expand SQL error detection and tolerate valid timing findings with expected server error responses.
- Bound crawler route saturation and restrict automatic redirect scope adoption to canonical host pairs by default.
- Correct reflection sentinel probes and dynamic payload assembly.
- Harden report-builder error handling and persist scan records before session start.

## [v0.1.7] - 2026-09-07

### Added

- GET-to-POST method pivoting with dual query/body hidden-parameter discovery.
- Automatic promotion of confirmed hidden POST parameters into scanner targets.
- Surface-adaptive module budgeting with per-category probe quotas and starvation isolation.
- Expanded high-impact parameter wordlists with context-aware prioritization for admin, cloud, upload and proxy routes.

### Fixed

- Preserve final scan status and avoid health-metrics nil pointer panics.
- Count request budgets outside retry loops and preserve HTTP 429 evidence with `Retry-After` handling.
- Use cryptographic randomness for WAF bypass headers and correct rate-limiter jitter.
- Tighten preflight, scope expansion, non-standard port handling, proxy port allocation and UTF-8 truncation behavior.

### Optimized

- Scope TLS misconfiguration checks to root hosts.
- Reduce noisy coverage notices in normal CLI output.
- Run `api_versioning` once per host on root or base API endpoints.

## [v0.1.6] - 2026-09-06

### Added

- Type-aware probing across SQL injection, command injection, NoSQL injection, IDOR/BOLA and path traversal modules.
- Numeric-safe SQL and command probes for parameters that reject free-form payload prefixes.
- Nested dotted-path support for MongoDB operator queries and authentication bypass bodies.
- Category-weighted request budgets with rollover from completed modules and groups.
- Coverage-gap metrics when configured budgets prevent full target coverage.

### Fixed

- Support bracket, dot and unindexed array JSON mutations without overwriting container values.
- Target only scalar JSON leaf values to avoid schema-validation rejections.
- Balance Windows and Linux traversal testing to avoid premature fast-fail behavior.

## [v0.1.5] - 2026-09-06

### Fixed

- Run WAF payload case randomization before encoding to preserve JavaScript and JSON escape syntax.
- Avoid WAF calibration double-encoding by checking URL-safe payloads before escaping.
- Replace permanent WAF throttling locks with temporary cautious mode and automatic recovery.
- Improve LiteSpeed header matching for cache and server fingerprints.
- Reduce SSRF, web cache deception and CRLF false positives with stricter proof checks.

### Optimized

- Accelerate CORS scanning with endpoint deduplication, route normalization, static asset skipping and host-scoped OAST probes.

## [v0.1.4] - 2026-09-05

### Optimized

- Increase default Chromium pool concurrency and align browser workers with session limits.
- Reduce CDP page settling delay and skip headless rendering for pages without scripts.
- Probe hidden-parameter wordlists with a concurrent worker pool.
- Persist only confirmed parameters during differential discovery to avoid downstream target inflation.

## [v0.1.3] - 2026-09-05

### Fixed

- Tighten OpenAI and Okta token detection with stricter patterns, entropy and character-diversity checks.
- Record redirect telemetry in the HTTP client for versioning checks.
- Reject redirected or HTML responses in `api_versioning` when they do not represent real API versions.

### Optimized

- Skip redundant reflection stability reprobes when no canary reflection is observed.
- Run reflection analysis through a configurable concurrent worker pool.

## [v0.1.2] - 2026-09-05

### Added

- Dynamic WAF character pre-flight calibration for critical syntax tokens.
- Context-aware WAF payload mutation for JSON, JavaScript, HTML attribute and XML reflections.
- Paired mutated negative controls for WAF-adapted offensive payloads.
- Block-aware payload scoring that prioritizes encodings which conceal filtered characters.

## [v0.1.1] - 2026-09-05

### Fixed

- Reduce false positives in sensitive files, cloud takeover, deep traversal, route auth bypass, CORS, WebSocket and sensitive-data checks.
- Add stronger credit-card and IBAN validation with checksum, context and known-test-number guards.
- Make sensitive-data proof matching specific to the reported type and value.
- Reduce HTTP request-smuggling and secret-exposure scan time with caching and duplicate-probe avoidance.
- Restore CRLF detection coverage for common parameter names and response-splitting evidence.
- Stop adding linked API/service subdomains to crawl scope by default.

### Added

- GitHub community, contribution and security documentation.
- `go install -v github.com/akha-security/akca/engine/cmd/akca@latest`
  installation instructions.
- `--include-linked-api-subdomains` to opt into the previous broad crawler scope
  expansion for linked API/service subdomains.

## [v0.1.0] - 2026-09-04

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

[Unreleased]: https://github.com/akha-security/akca/compare/v0.2.3...HEAD
[v0.2.3]: https://github.com/akha-security/akca/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/akha-security/akca/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/akha-security/akca/releases/tag/v0.2.1
[v0.2.0]: https://github.com/akha-security/akca/releases/tag/v0.2.0
[v0.1.9]: https://github.com/akha-security/akca/releases/tag/v0.1.9
[v0.1.8]: https://github.com/akha-security/akca/releases/tag/v0.1.8
[v0.1.7]: https://github.com/akha-security/akca/releases/tag/v0.1.7
[v0.1.6]: https://github.com/akha-security/akca/releases/tag/v0.1.6
[v0.1.5]: https://github.com/akha-security/akca/releases/tag/v0.1.5
[v0.1.4]: https://github.com/akha-security/akca/releases/tag/v0.1.4
[v0.1.3]: https://github.com/akha-security/akca/releases/tag/v0.1.3
[v0.1.2]: https://github.com/akha-security/akca/releases/tag/v0.1.2
[v0.1.1]: https://github.com/akha-security/akca/releases/tag/v0.1.1
[v0.1.0]: https://github.com/akha-security/akca/releases/tag/v0.1.0

