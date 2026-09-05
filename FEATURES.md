# Why AKCA

AKCA Advanced Web Security Scanner is built around a simple product idea:
security findings should arrive with enough evidence to be reviewed, reproduced,
and fixed—not merely with a matched response string.

This document is the detailed product tour. For installation and CLI examples,
see the [README](README.md).

## The defining difference: an evidence contract

Traditional dynamic scanning often starts and ends with a heuristic: a payload
was sent, a suspicious string appeared, so an alert was created. AKCA separates
**candidate detection** from **finding publication**.

A module can require one or more of the following before a candidate reaches a
primary report:

- A clean native baseline
- A positive probe with a typed security signal
- A negative or syntax control
- Independent deterministic replay
- A true/false boolean response pair
- Statistically calibrated timing evidence
- A scan-bound DNS or HTTP OAST callback
- Browser-confirmed DOM execution
- A runtime sensor trace
- Cross-role or cross-identity authorization proof
- A verified state mutation and cleanup sequence
- Retrieval of a safely uploaded test artifact

Candidates that do not satisfy their module's proof policy are suppressed or
retained as clearly separated manual leads. This architecture aims to reduce
triage noise without reducing the scanner's available modules.

## Modern attack-surface discovery

AKCA combines discovery sources that are often separate tools.

### Concurrent HTTP crawling

- Scope-aware redirect handling
- Route-template normalization
- Query-variant deduplication
- Explicit-host crawling by default; linked API/service subdomains are opt-in
- Crawl-trap and calendar-loop detection
- Method-correct HTML form extraction
- POST/PUT/PATCH request-template retention
- Passive secret and sensitive-data inspection during crawling
- Endpoint prioritization and configurable budgets

### Browser-backed SPA discovery

- Chrome, Chromium, or Edge execution through the DevTools Protocol
- Rendered DOM capture
- XHR/fetch request and response metadata
- Request bodies for real POST/PUT/PATCH calls
- Browser Console and JavaScript exception capture
- WebSocket and service-worker discovery
- Cookie, local-storage and session-storage state capture
- DOM sink instrumentation for client-side vulnerability evidence

### JavaScript intelligence

- Endpoint extraction from fetch, XHR, axios and template literals
- SPA route discovery
- WebSocket URL discovery
- Secret and credential pattern analysis
- Passive secret evidence caching to avoid repeated scans of identical bodies
- Source-map discovery and inspection
- Imported and third-party script analysis

These sources are normalized into a shared inventory instead of being reported
as disconnected crawl results.

## API-native security testing

AKCA understands API contracts as executable discovery input. It supports:

- OpenAPI 3.0 and 3.1
- Swagger 2.0
- RAML 1.0 and multi-file `!include` bundles
- Postman collections and environments
- HAR traffic exports
- GraphQL schemas
- WSDL services
- protobuf/gRPC definitions
- AsyncAPI channels

OpenAPI external `$ref` files and RAML includes can be supplied as bounded ZIP
bundles. AKCA resolves schemas, creates representative request bodies, extracts
typed JSON leaf parameters, and keeps the declared HTTP method. A discovered GET
route is never converted into an invented POST request merely to create more
tests.

## Vulnerability coverage

The current catalog contains more than 80 registered checks. Major families
include the following.

### Injection and execution

- SQL injection: error, boolean, timing, union, stacked and OAST strategies
- NoSQL injection
- Reflected, DOM, stored and blind XSS
- Command injection
- Server-side and client-side template injection
- XXE, LDAP and XPath injection
- Server-side JavaScript injection
- Unsafe deserialization
- CRLF/header and response-splitting injection, including common parameter names
- Prototype pollution
- LLM prompt-injection signals

### APIs, identity and business logic

- BOLA/IDOR and tenant isolation
- Broken function-level authorization
- Authentication and route-normalization bypasses
- JWT validation and trust-boundary checks
- OAuth/OIDC flow auditing
- Mass assignment and hidden-field binding
- HTTP parameter pollution
- CSRF and session lifecycle
- Account recovery and webhook policies
- Rate limits and synchronized race conditions
- Stateful business-logic checks with cleanup contracts

### Infrastructure and exposure

- TLS protocols, ciphers and certificate problems
- CSP, COOP, cookie and security-header weaknesses
- Chrome Logger debug-data exposure
- Public configuration, backup, source and Git artifacts
- Exposed installer/setup wizards with multi-signal validation
- CI/CD, cloud-storage and cloud-native exposure
- Spring Actuator/Jolokia and framework debug surfaces
- Swagger/OpenAPI and GraphQL exposure
- Web cache poisoning/deception and CPDoS
- Host-header poisoning and proxy path confusion
- HTTP/1.1 and HTTP/2 request-smuggling signals
- WebSocket and cross-site WebSocket hijacking checks
- Technology inventory and version-bound CVE matching

Some state-changing checks require an operator-supplied proof policy containing
the allowed action, state read, negative control, and cleanup request. AKCA does
not invent destructive workflows for an unknown application.

## False-positive resistance

AKCA's noise controls are evidence checks—not censorship controls:

- Semantic baseline comparison for HTML, JSON, headers and status behavior
- Generic error-page and soft-404 rejection
- WAF block-page identification
- Wildcard route and SPA fallback detection
- Negative-control comparison
- Replay stability requirements
- Timing baseline calibration instead of a single fixed delay threshold
- Reflection-context and output-encoding analysis
- Content fingerprints for exposed files and installer pages
- Exact TLS handshakes for legacy protocol and weak-cipher claims
- Version-bound CVE matching; unknown versions do not become CVE findings

WAF intelligence can reduce concurrency or reorder payloads, but it does not
remove vulnerability classes from the scanner. Furthermore, when a WAF is identified
(Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, etc.), AKCA automatically derives
vendor-adapted payload mutations using intelligent encoding strategies—such as URL / double-URL
encoding, Unicode NFKC normalization, comment-splitting, case alternation, and HTML entity
transformations—to ensure vulnerabilities are not hidden behind superficial payload filtering.

Recent hardening also reduced unnecessary work without narrowing the detector
set: request-smuggling controls are reused per route, unsupported HTTP/2 ALPN is
remembered per origin, passive secret exposure does not replay identical
requests, and crawler linked-subdomain expansion is disabled unless the operator
explicitly opts in.

## Designed for long-running assessments

- SQLite-backed scan state and evidence
- Phase checkpointing and interrupted-scan resume
- Global and per-host rate limits
- Global and crawler request budgets
- Time, memory, endpoint and page limits
- Opt-in linked API/service subdomain expansion for broader crawls
- Adaptive WAF-aware traffic pacing
- Pre-scan connectivity and authentication validation
- Immediate termination on an initial HTTP 502 gateway failure
- Authentication heartbeat and automatic re-login support
- OAST server failover and configurable drain windows
- Finding correlation and root-cause grouping

## Reports built for action

Every supported report format is produced from the same evidence ledger:

- **HTML:** standalone interactive report
- **JSON:** versioned machine-readable schema
- **Markdown:** developer and ticket-friendly evidence
- **CSV:** configurable audit export
- **SARIF:** CI and code-scanning ingestion

Depending on the selected template, output may contain raw HTTP exchanges,
payloads, response markers, typed observations, replay commands, confidence
explanations, remediation guidance, CWE identifiers, and OWASP Top 10:2025
categories. Automatic redaction protects authorization headers, cookies, tokens,
API keys and credentials in stored/exported material.

## Where AKCA stands apart

AKCA is not trying to win by sending the largest payload list. Its strongest
product characteristics are:

1. **Proof is a first-class data type.** Verification is part of the engine,
   rather than prose added to a report after detection.
2. **Discovery preserves reality.** Real browser traffic, API methods and body
   schemas survive into the testing plan.
3. **Active coverage and reporting confidence are separate.** A module can run
   without every weak signal becoming a published vulnerability.
4. **Stateful checks are explicit and recoverable.** High-impact workflows can
   demand state reads and cleanup instead of making unsafe guesses.
5. **Evidence remains useful after the scan.** Checkpoints, stored observations,
   replay commands and multiple report formats support engineering workflows.
6. **The core is open and inspectable.** Teams can review proof policies, add
   modules, contribute fixtures and challenge detection assumptions.

## Who it is for

- Application-security engineers who need reproducible DAST evidence
- Penetration testers working within authorized scopes
- Developers validating staging deployments
- Security researchers building or evaluating detection logic
- Teams that want SARIF/JSON automation without losing raw proof context

## Project maturity

`v0.1.0` is an early public release. AKCA has an extensive automated test suite,
but no scanner can guarantee complete vulnerability coverage or zero false
positives. Production adoption should begin with controlled staging targets,
explicit budgets, and human review.

Contributions are welcome at
[github.com/akha-security/akca](https://github.com/akha-security/akca).
