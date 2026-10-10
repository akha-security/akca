# Changelog

All notable changes to AKCA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [v0.2.8] - 2026-10-10

### Added

- Add parser tomography for observed URL decode depth and plus-to-space behavior, with persisted WAF decoder profiles.
- Add atomic runtime WAF variant sets so SQL boolean pairs, timing delays and matched controls always receive the same transformation.
- Add independent browser-backed DOM XSS execution proof for non-reflected client-side flows, including clean baseline controls and CSP-tolerant canary fallbacks.
- Add regression coverage for HTTP 556 preflight handling, narrow scan modes, host circuit recovery, passive response reuse, SSRF reflection filtering, discovery-document exclusion and DOM XSS controls.

### Changed

- Treat failed or blocked payload variants as diagnostic observations when the same target still produced usable module coverage, preventing false `PARTIAL` module results.
- Apply compound WAF techniques through one transformation path and preserve UTF-8, SQL keyword grammar and exact URL-encoding depth.
- Generate dynamic encoded SQL timing and boolean variants with matched zero-delay and false-branch controls.
- Share captured response bodies across passive exposure analyzers and allow incomplete captured bodies to provide positive evidence without a network refetch.
- Pace backup archive probes per origin, prioritize high-yield candidates and stop expansion at the first pressure signal or verified archive.
- Gate browser crawling to application-shell/runtime surfaces, bound hidden-parameter concurrency globally, batch safe candidate prefilters and avoid redundant cross-endpoint rediscovery.
- Keep directory fuzzing and 403-bypass testing disabled for narrow `--mode` scans unless explicitly selected.
- Continue scanning through nonstandard gateway/WAF statuses such as HTTP 556 while retaining fail-fast behavior for registered server errors.

### Fixed

- Reject SSRF candidates caused by encoded payload reflection, script/analytics echoes, hostname-only matches and generic body differences; require provider-specific metadata structure for high-confidence signals.
- Honor `429`, `Retry-After` and WAF challenge pressure through a host circuit that waits and resumes instead of flooding the origin or skipping queued modules.
- Preserve deliberate rate-limit `429` responses as module evidence without opening the global WAF circuit for unrelated scan traffic.
- Avoid repeated active parameter probing of `robots.txt`, sitemap and `.well-known` discovery documents.
- Prevent DOM XSS from being discarded merely because the server response is unchanged, while rejecting pre-existing browser execution markers and non-replayable header/body surfaces.
- Avoid unnecessary network traffic in passive vulnerable-component and offline CVE catalog modules.

### Validation

- Full Go package tests pass with `go test ./... -count=1`.
- Static analysis passes with `go vet ./...`.
- The strict observed benchmark gate passes before release tagging; the advisory complete-corpus audit continues to publish outstanding per-module fixture coverage.
- Release assets are built for Windows x64, Linux x64/ARM64 and macOS Intel/Apple Silicon with SHA-256 checksums and GitHub provenance attestations.

## [v0.2.7] - 2026-10-04

### Changed

- Generate collision-resistant scan identifiers automatically and allow independent scan processes to share the WAL-backed SQLite store without a machine-wide scan lock.
- Remove the implicit per-URL module budget from Full Scan so SQL injection and other finite module workflows are not silently truncated; explicit operator budgets remain supported.
- Bound hidden-parameter discovery around prioritized Arjun-style probing instead of promoting every observed value into a parameter candidate.
- Reject HTTP 200 WAF block pages as Server-Side JavaScript timing evidence and require three statistically consistent delayed probes against three matched zero-delay controls.

## [v0.2.6] - 2026-10-03

### Added

- Add provider-specific SSRF response validation for Alibaba Cloud, DigitalOcean, Oracle Cloud, Tencent Cloud and Packet/Equinix Metal metadata, plus stronger Docker, Consul, Redis and Kubernetes signals.
- Add failover-domain, unhealthy-listener and per-payload OAST regression coverage.
- Add stricter benchmark, browser and protocol-smuggling regressions, plus an explicit complete-corpus coverage audit for missing module fixtures.

### Changed

- Cap and parallelize hidden-parameter cross-endpoint discovery so full-coverage scans retain useful depth without unbounded request growth.
- Increase the full-scan crawler limit from 1,000 to 1,500 pages.
- Improve automatic memory-limit selection across Windows and Linux and simplify the terminal resource labels to `Scan` and `Total`.
- Preserve endpoint discovery while bounding crawler traffic and improve form, traversal and payload scheduling behavior.

### Fixed

- Preserve callbacks issued before an OAST provider failover by correlating them against the provider domain captured at registration time.
- Assign a distinct one-time OAST callback identity to every SSRF/WAF payload variant so evidence cannot be overwritten by a later probe.
- Disable blind OAST coverage when the end-to-end preflight callback fails instead of advertising an unusable listener as ready.
- Correct malformed double-scheme callback URLs in PDF injection and Server-Side JavaScript probes.
- Reduce false positives and missed signals across blind XSS, SQL injection, command injection, LFI, SSRF, DOM XSS, HTTP smuggling and source-disclosure verification.

### Validation

- Full Go package tests pass with `go test ./... -count=1`.
- Static analysis passes with `go vet ./...`.
- Release assets are built for Windows x64, Linux x64/ARM64 and macOS Intel/Apple Silicon with SHA-256 checksums and GitHub provenance attestations.

## [v0.2.5] - 2026-09-28

### Added

- Add directory-listing discovery for common content roots, inferred parent directories from observed static assets, and structural Apache/nginx/Python/IIS listing detection with CWE-548 reporting.
- Add machine-readable assurance profiles for every runnable module, including OWASP ASVS, WSTG and API Security Top 10 mappings, required request surfaces, capabilities and benchmark contracts.
- Add a fail-closed `akca benchmark --complete-corpus` release gate that requires positive and negative observed fixtures for every module and rejects capability skips.
- Add end-to-end OAST self-testing, explicit browser/OAST/identity/workflow/runtime capability matrices and automatic role-profile inference from distinct configured authentication profiles.
- Add XML, multipart, raw GraphQL, WebSocket JSON, observed-header and positional path-identifier mutation surfaces.
- Add paired SQL boolean-oracle and numeric arithmetic-oracle regression coverage for search, login and numeric identifier surfaces.
- Add cryptographically signed GitHub build-provenance attestations for every release binary.
- Add blind boolean LDAP and XPath injection verification with expanded vendor and parser error signatures.
- Add Velocity, Smarty and Razor SSTI probes plus string-transform execution checks that do not depend only on arithmetic evaluation.
- Add dynamic MSSQL `WAITFOR DELAY` timing probes, Windows PowerShell/cmd command-injection variants and the Unix `||id` operator family.
- Add heuristic single-profile IDOR testing and a broader tenant, organization, workspace, team, project and company identifier dictionary while preserving multi-role ownership proofs.
- Add route authorization-bypass variants for encoded slashes, case normalization and `X-HTTP-Method-Override`, including safe-read fallback for non-GET endpoints.
- Add IPv6, IPv4-mapped IPv6, hexadecimal/octal, zero-address and gopher/dict SSRF variants.
- Add takeover fingerprints for AWS CloudFront and Elastic Beanstalk, Azure CDN, Google Cloud Run, Render, Tilda and Canny.
- Add cache-poisoning parameter-cloaking verification with anonymous replays and a cold negative control.

### Changed

- Expand SSRF URL-parser and cloud-metadata variants, deserialization format coverage, LLM indirect/RAG/tool-boundary probes, TLS key/signature/cipher analysis, HSTS validation and executable CSP-source checks.
- Auto-admit exact cross-origin hosts discovered only from passive HTML/CSP dependencies, while keeping active requests out of scope and stripping credentials.
- Publish response usability, authentication/rate/gateway blocks, transport failures and proof-observation roles in module coverage events.
- Preserve captured browser requests as the preferred replay template, including duplicate parameters and case-insensitive HTTP header identity.
- Publish proof-policy suppression reasons in machine-readable and HTML/Markdown coverage diagnostics.
- Validate the curated CVE snapshot at startup, publish provenance/freshness metadata and fail closed for incomplete component identities.
- Embed release version, commit and build date in `akca --version` and generated reports.
- Stream report findings with cancellation support and a bounded fast-partial path after Ctrl+C.

### Fixed

- Hide OAST preflight health callbacks from vulnerability cards and exclude them from the final OAST hit count.
- Correct request mutation for XML, multipart and raw GraphQL bodies and extend path mutation to UUID, ULID, hash and high-entropy identifiers.
- Prevent configured browser or OAST flags from being treated as working capabilities until the underlying browser/callback path is actually usable.
- Replace destructive SQL syntax controls with clean native-value controls and compare normalized visible response content to resist padding noise.
- Distinguish browser-confirmed reflected XSS from true DOM-based XSS in live finding labels and evidence signals.

### Validation

- Full Go package tests pass with `go test ./... -count=1`.
- Static analysis passes with `go vet ./...`.
- Strict observed-corpus quality gates retain 1.0 precision and an F1 score above 0.96.
- Release binaries are built for Windows x64, Linux x64/ARM64 and macOS Intel/Apple Silicon with SHA-256 manifests and GitHub provenance attestations.

## [v0.2.4] - 2026-09-26

### Added

- Add a self-contained AKCA-branded HTML report with an embedded logo, vulnerability summary table, detailed finding sections, and print-safe styling.
- Add Request, Response, and combined HTTP evidence views with full-content expansion and clipboard controls.
- Add a Lipgloss-based Scan Session panel with target emphasis, active-state display, crawl policy, engine, authentication, transport, OAST, request-rate, and RAM summaries.
- Add friendly terminal labels for vulnerability modules and in-place transitions from Running to Completed.
- Add an English workflow and security-testing capability guide plus Turkish and international community-support messages.

### Changed

- Render structured-only request evidence in a conventional Burp-style layout with ordered request headers, content type and length, connection policy, and a clear header/body boundary.
- Include standard HTTP reason phrases in reconstructed responses while preserving captured raw transactions verbatim when available.
- Replace estimated completion time with a continuously updating elapsed timer in live scan status.
- Split `-h` into concise help and `--help` into the complete command reference; remove unsupported domain and positional-target forms from usage and parsing.
- Aggregate browser dependency blocks and keep repetitive coverage diagnostics in verbose CLI output while retaining coverage events for reports and machine-readable consumers.
- Replace the previous README image with reproducible output captured from the local integration lab.

### Fixed

- Preserve nested and flat raw request/response fields instead of rebuilding and shortening them during report generation.
- Preserve long response bodies, repeated response headers, request/response trailing whitespace, and explicit transport truncation state.
- Distinguish module coverage gaps from execution failures so incomplete targets do not produce misleading scan-error output.
- Improve adaptive module accounting and crawler coverage summaries for failed, unfinished, and browser-blocked work.

### Validation

- Full Go package tests pass with `go test ./... -count=1`.
- Static analysis passes with `go vet ./...`.
- Report regressions cover raw transaction preservation, long and escaped response bodies, missing or truncated evidence, tab controls, print output, and clipboard paths.
- Windows executable reports `AKCA ADVANCED WEB SECURITY SCANNER v0.2.4`.

## [v0.2.3] - 2026-09-25

### Added

- Add a redesigned HTML security report with an executive risk overview, severity distribution, scan metadata and structured vulnerability statistics.
- Add dedicated finding sections for affected endpoints, impact, classification and remediation guidance.
- Add a transaction-focused request and response viewer with outbound/inbound context, method or status details, proof highlighting and clipboard controls.
- Add a prominent partial-coverage warning when scan gaps prevent a clean result from representing complete assurance.

### Changed

- Replace the scan-session card with a purpose-built Scan Control dashboard covering target, profile, discovery, verification and traffic policy.
- Refine the live progress row with readable URL counts, professional status text and suppression of meaningless zero-rate output.
- Format large counters and memory limits consistently for terminal readability.
- Remove the standalone Coverage & Readiness section from HTML and Markdown output while retaining coverage metadata and the partial-scan warning.
- Document why comprehensive Full Scans take longer and how to request faster, bounded feedback safely.

### Validation

- Full Go package tests pass with `go test ./... -count=1`.
- CLI and report static analysis passes with `go vet ./cmd/akca ./internal/report`.
- Report regression tests cover the risk dashboard, severity statistics, partial-scan warning and transaction evidence viewer.

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

[Unreleased]: https://github.com/akha-security/akca/compare/v0.2.8...HEAD
[v0.2.8]: https://github.com/akha-security/akca/compare/v0.2.7...v0.2.8
[v0.2.7]: https://github.com/akha-security/akca/compare/v0.2.6...v0.2.7
[v0.2.6]: https://github.com/akha-security/akca/compare/v0.2.5...v0.2.6
[v0.2.5]: https://github.com/akha-security/akca/compare/v0.2.4...v0.2.5
[v0.2.4]: https://github.com/akha-security/akca/compare/v0.2.3...v0.2.4
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

