<h1 align="center">AKCA Advanced Web Security Scanner</h1>
<img width="2172" height="724" alt="banner" src="https://github.com/user-attachments/assets/aa8571ac-4c65-44a6-b723-abe53450e8bf" />

<p align="center">
  <strong>Evidence-driven dynamic application security testing, built in Go.</strong><br>
  Discover the real attack surface. Verify the behavior. Report the evidence.
</p>

<p align="center">
  <a href="https://github.com/akha-security/akca/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/akha-security/akca/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/akha-security/akca/releases"><img alt="Version" src="https://img.shields.io/badge/version-v0.1.1-6f42c1"></a>
  <a href="https://go.dev/"><img alt="Go" src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
</p>

AKCA is an open-source DAST engine focused on a problem security teams know too
well: a scanner result is only useful when engineers can trust and reproduce it.
Instead of promoting every response anomaly to a vulnerability, AKCA records a
baseline, exercises a targeted probe, applies vulnerability-specific controls,
and stores the evidence used to reach its decision.

> [!IMPORTANT]
> AKCA is currently an early `v0.1.1` release. Use it on systems you own or are
> explicitly authorized to test, validate findings before acting on them, and
> avoid production-impacting scan profiles without an agreed test window.

## Why AKCA?

- **Evidence contracts instead of signature-only alerts.** Findings can require
  negative controls, deterministic replay, identity boundaries, state changes,
  DOM execution, runtime traces, or correlated OAST callbacks.
- **Discovery that understands modern applications.** A concurrent HTTP crawler,
  Chromium DOM execution, browser Network/Console capture, JavaScript analysis,
  source maps, forms, WebSockets, and service workers feed one normalized inventory.
- **API-native scanning.** Import OpenAPI 3.0/3.1, RAML bundles, Postman, HAR,
  WSDL, GraphQL, protobuf, and AsyncAPI definitions—including POST request bodies.
- **False-positive resistance without disabling capabilities.** WAF awareness
  changes pacing and payload ordering; it does not silently remove scan modules.
- **Operationally useful output.** SQLite checkpoints, scan resume, finding replay,
  root-cause grouping, redaction, and HTML/JSON/Markdown/CSV/SARIF reports.
- **A broad security surface.** The current module catalog registers 80+ checks
  across injection, authorization, authentication, API, browser, cloud, protocol,
  exposure, and business-logic categories.

Read [FEATURES.md](FEATURES.md) for the complete capability tour and the design
choices that distinguish AKCA.

## How verification works

```text
Target / API definition
        │
        ▼
Preflight ──► fingerprint and WAF calibration
        │
        ▼
HTTP + browser + JavaScript + API discovery
        │
        ▼
Parameter and reflection analysis
        │
        ▼
Targeted probe ──► negative control ──► replay / identity / state / OAST proof
        │
        ▼
Evidence ledger ──► report gate ──► HTML · JSON · Markdown · CSV · SARIF
```

A response difference is a lead, not automatically a finding. AKCA's proof
policy engine can suppress candidates caused by generic error pages, WAF block
pages, unstable baselines, timing noise, honeypot parameters, failed controls,
or non-reproducible behavior. Passive configuration and content findings follow
their own direct-evidence policies.

## Installation

### Install with Go

The fastest way to install AKCA from GitHub is:

```bash
go install -v github.com/akha-security/akca/engine/cmd/akca@latest
```

Make sure your Go binary directory is on `PATH`:

```bash
# Linux/macOS
export PATH="$(go env GOPATH)/bin:$PATH"

# Windows PowerShell
$env:Path += ";$(go env GOPATH)\bin"
```

Then verify the install:

```bash
akca --version
akca --help
```

### Build from source

Requirements:

- Go `1.25` or newer
- Git
- Optional: Chrome, Chromium, or Edge for browser-backed SPA discovery

Linux and macOS:

```bash
git clone https://github.com/akha-security/akca.git
cd akca/engine
go build -buildvcs=false -trimpath -o ../akca ./cmd/akca
../akca --version
```

Windows PowerShell:

```powershell
git clone https://github.com/akha-security/akca.git
Set-Location akca\engine
go build -buildvcs=false -trimpath -o ..\akca.exe .\cmd\akca
..\akca.exe --version
```

Release binaries, when published, are available from
[GitHub Releases](https://github.com/akha-security/akca/releases).

## Quick start

```bash
# Full scan
./akca -u https://staging.example.com

# Focused SQL/NoSQL injection scan
./akca -u https://staging.example.com -m sql

# Combine profiles
./akca -u https://staging.example.com -m sql,xss,api

# Authenticated scan
./akca -u https://app.example.com \
  -c "session=replace-me" \
  -H "Authorization: Bearer replace-me"

# API scan using a multi-file OpenAPI or RAML ZIP bundle
./akca -u https://api.example.com \
  --api-spec ./api-bundle.zip \
  -m api

# Passive, non-mutating inspection
./akca -u https://staging.example.com -m passive -v

# Crawl linked API/service subdomains only when you explicitly want wider scope
./akca -u https://www.example.com \
  --include-linked-api-subdomains

# Send traffic through an inspection proxy
./akca -u https://staging.example.com \
  -p http://127.0.0.1:8080 -k

# Generate SARIF for CI systems
./akca -u https://staging.example.com \
  -f sarif -o results.sarif -q
```

Run `akca --help` for the complete CLI reference.

## Scan profiles

Profiles are explicit user choices. They select a focused module set; AKCA does
not remove individual capabilities merely because a WAF was detected.

| Profile | Focus |
| --- | --- |
| `full` | Complete active and passive assessment |
| `sql` | SQL and NoSQL injection |
| `xss` | Reflected, DOM, stored and blind XSS; client-side injection |
| `api` | REST/JSON, BOLA/IDOR, BFLA, JWT, OAuth and mass assignment |
| `graphql` | Introspection, schema and GraphQL operation security |
| `rce` | Command injection, SSTI and unsafe deserialization |
| `ssrf` | SSRF, XXE and correlated out-of-band checks |
| `auth` | Authentication, authorization, CSRF, cookie and session checks |
| `passive` | Non-mutating metadata, TLS, header, secret and exposure analysis |
| `fuzz` | Path, archive, source disclosure and infrastructure discovery |

## API definition support

AKCA turns imported operations into the same normalized endpoint inventory used
by crawling. Typed query, path, header and JSON-body parameters become candidate
injection points while preserving the operation's real HTTP method.

By default, crawling stays inside the explicitly configured target hosts. Linked
API/service subdomains such as `api.example.com`, `backend.example.com`, or
`graphql.example.com` are not auto-added to scope unless you pass
`--include-linked-api-subdomains` or include those hosts explicitly, for example
with a wildcard scope.

| Format | Highlights |
| --- | --- |
| OpenAPI / Swagger | OpenAPI 3.0/3.1 request bodies, local and bundled external `$ref` schemas |
| RAML 1.0 | Resources, methods, typed bodies, nested routes and bundled `!include` files |
| Postman | Collections plus environment variable expansion |
| HAR | Captured request methods, URLs and parameters |
| GraphQL | Typed variables and valid selection templates |
| WSDL | SOAP service and operation discovery |
| protobuf | gRPC service and RPC discovery |
| AsyncAPI | Publish/subscribe channel inventory |

ZIP imports enforce path traversal, entry count, per-file size, and total
expanded-size limits before resolving bundled definitions.

## Reports and evidence

AKCA exports:

- Interactive, standalone HTML
- Stable JSON with an explicit schema version
- Developer-oriented Markdown
- Customizable CSV
- SARIF 2.1.0 for code-scanning pipelines

Reports can include raw HTTP evidence, payloads, response markers, proof-policy
status, typed observations, reproduction commands, confidence explanations,
CWE mappings, and OWASP Top 10:2025 categories. Credentials, cookies, tokens,
and authorization headers can be redacted before storage or export.

Replay a stored finding independently:

```bash
./akca replay --finding 42
```

## CI example

```yaml
- name: Build AKCA
  working-directory: engine
  run: go build -buildvcs=false -trimpath -o ../akca ./cmd/akca

- name: Scan staging
  run: |
    ./akca -u "${{ secrets.STAGING_URL }}" \
      -m sql,xss,api \
      --time-budget 30m \
      --request-budget 5000 \
      -f sarif -o results.sarif -q

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Never place credentials directly in a workflow file. Use repository or
environment secrets and scan only an approved staging target.

## Architecture

The engine lives under `engine/` and is split into focused internal packages:

- `app`: scan lifecycle and phase orchestration
- `crawler` and `browserpool`: HTTP/browser discovery and runtime capture
- `apinative`: API definition import and request materialization
- `reflection` and `payloadgen`: context analysis and payload synthesis
- `modules`: vulnerability checks and scheduling
- `verification`: evidence contracts and proof-policy enforcement
- `oast`: callback registration, polling and correlation
- `storage`: SQLite evidence, checkpoint and scan state
- `report`: HTML, JSON, Markdown, CSV and SARIF generation

See [engine/docs/ARCHITECTURE.md](engine/docs/ARCHITECTURE.md) and
[engine/docs/FALSE_POSITIVE_AUDIT.md](engine/docs/FALSE_POSITIVE_AUDIT.md) for
the deeper technical model.

## Development

```bash
cd engine
go test ./... -count=1
go vet ./...
go build -buildvcs=false ./cmd/akca
```

The repository also includes a deterministic quality benchmark:

```bash
cd engine
go run ./cmd/akca benchmark --strict
```

Recent scanner hardening focused on preserving capability while reducing wasted
work: request-smuggling probes are route-scoped and cache protocol controls,
secret exposure is treated as passive content evidence, CRLF no longer skips
common parameter names, and linked API subdomain expansion is opt-in.

Before opening a pull request, read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Project status

AKCA is under active development. APIs, report schemas, module behavior, and CLI
flags may evolve before `v1.0.0`. Bug reports, test fixtures, documentation fixes,
and carefully scoped detection improvements are welcome.

## Security and responsible use

Only scan assets you own or have explicit written permission to assess.
Aggressive modules may change application state when an operator supplies the
required state/cleanup policies. Start with a staging environment and an agreed
request budget.

To report a vulnerability in AKCA itself, follow [SECURITY.md](SECURITY.md).
Do not publish target credentials, customer data, or third-party vulnerability
details in a public GitHub issue.

## License

Copyright 2026 AKHA Security contributors.

Licensed under the [Apache License 2.0](LICENSE).

---

If AKCA helps your security workflow, consider starring the repository and
sharing reproducible test cases: [github.com/akha-security/akca](https://github.com/akha-security/akca).
