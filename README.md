<h1 align="center">AKCA Advanced Web Security Scanner</h1>

<p align="center">
  <strong>Discover the attack surface. Test the behavior. Inspect the evidence.</strong><br>
  An open-source dynamic application security testing engine, built in Go.
</p>

<p align="center">
  <a href="https://github.com/akha-security/akca/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/akha-security/akca/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/akha-security/akca/releases/tag/v0.2.0"><img alt="Version v0.2.0" src="https://img.shields.io/badge/version-v0.2.0-8b5cf6"></a>
  <a href="https://go.dev/"><img alt="Go 1.25 or newer" src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white"></a>
  <a href="LICENSE"><img alt="Apache License 2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
</p>

<p align="center">
  <a href="#installation">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#scan-profiles">Profiles</a> ·
  <a href="#reports-and-evidence">Reports</a> ·
  <a href="FEATURES.md">Features</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

AKCA brings HTTP crawling, browser discovery, API imports and vulnerability checks
into one workflow. It records the requests, responses and verification context
behind a finding so you can inspect what happened and reproduce it.

> Use AKCA only on systems you own or have explicit permission to assess.
> Start with an authorized staging target and appropriate traffic limits.

## What AKCA does

| Capability | What you get |
| --- | --- |
| Surface discovery | HTTP crawling, browser-assisted discovery, JavaScript analysis, forms and hidden parameters |
| API-aware testing | Imported operations and request templates preserve HTTP methods and parameter locations |
| Active and passive checks | Injection, access control, authentication, API, cloud, configuration and exposed-data checks |
| Verification | Module-specific controls, replay, timing comparisons, browser observations and OAST correlation where supported |
| Adaptive budgets | Module and URL allocations protect later targets' reserved requests |
| Inspectable evidence | SQLite records, raw HTTP evidence, reproduction commands and five report formats |

See [FEATURES.md](FEATURES.md) for the capability tour and
[the architecture guide](engine/docs/ARCHITECTURE.md) for the engine design.

### New in v0.2.0

- URL-based module budgets, unused-budget rollover and visible incomplete-coverage notices.
- Broader SQL probe coverage and preservation of POST body parameters in fallback targets.
- Yellow response highlights for recorded matching values, plus response excerpts
  for passive secrets and supported JavaScript and script-reference findings.

Read the [changelog](CHANGELOG.md) for details.

## Installation

### Download a binary

Get the build for your operating system from [GitHub Releases](https://github.com/akha-security/akca/releases/latest).
The release also includes `SHA256SUMS.txt` for checksum verification.

| Platform | Release asset |
| --- | --- |
| Windows x64 | `akca-windows-amd64.exe` |
| Linux x64 / ARM64 | `akca-linux-amd64` / `akca-linux-arm64` |
| macOS Intel / Apple Silicon | `akca-darwin-amd64` / `akca-darwin-arm64` |

On Windows, rename the downloaded file to `akca.exe`, then run from PowerShell:

```powershell
.\akca.exe --version
.\akca.exe --help
```

On Linux or macOS, make your downloaded binary executable. For example, on Linux x64:

```bash
chmod +x akca-linux-amd64
./akca-linux-amd64 --version
```

The examples below use `akca` on `PATH`. Use `./akca` or `.\akca.exe` when running
directly from a local directory.

### Install with Go

Requires Go **1.25 or newer**:

```bash
go install github.com/akha-security/akca/engine/cmd/akca@latest
akca --version
```

If `akca` is not found, add your Go binary directory to `PATH`.
For a default Go installation:

```bash
# Linux / macOS
export PATH="$(go env GOPATH)/bin:$PATH"
```

```powershell
# Windows PowerShell
$env:Path += ";$(go env GOPATH)\bin"
```

Chrome, Chromium or Edge is needed for browser-backed checks. Those checks depend
on browser availability and configuration; an HTTP-only run does not establish
browser execution coverage.

## Quick start

Replace the example host with an authorized target.

```bash
# Full scan with traffic and time limits; save an HTML report
akca -u https://staging.example.com --request-budget 5000 --time-budget 30m -o report.html

# Focus on SQL injection, XSS and server-side injection
akca -u https://staging.example.com -m sql,xss,rce

# Passive inspection (still sends discovery and inspection requests)
akca -u https://staging.example.com -m passive
```

### Authentication, APIs and proxies

```bash
# Supply an authorized session cookie or header
akca -u https://staging.example.com -c "session=replace-me"
akca -u https://staging.example.com -H "Authorization: Bearer replace-me"

# Import an API definition or a supported multi-file ZIP bundle
akca -u https://api.example.com --api-spec ./api-bundle.zip -m api

# Inspect traffic through a local proxy
akca -u https://staging.example.com -p http://127.0.0.1:8080
```

Use `akca --help` for all options. Supplying a session alone does not establish
the multiple identities or state policies required by some authorization checks.

## Scan profiles

Combine profiles with commas, for example `-m sql,xss,api`. The default is `full`.

| Profile | Focus |
| --- | --- |
| `full` | All enabled active and passive modules |
| `sql` | SQL and NoSQL injection |
| `xss` | Reflected, stored, DOM and blind XSS; related client-side checks |
| `rce` | Command injection, SSTI, deserialization and related injection checks |
| `api` | API exposure, BOLA/IDOR, BFLA, mass assignment and token checks |
| `graphql` | GraphQL schema and operation checks |
| `ssrf` | SSRF, XXE and related out-of-band checks |
| `auth` | Authentication, authorization, CSRF and cookie/header checks |
| `passive` | Metadata, TLS, headers, secrets and component analysis |
| `fuzz` | Paths, exposed artifacts, traversal and related checks |

Profiles select modules; execution still depends on discovered surfaces,
configuration, available verification capabilities and remaining budgets.

## Scope and request budgets

Crawling stays within configured target scope. Linked API/service subdomains are
not automatically included. To include linked subdomains under the same root:

```bash
akca -u https://www.example.com --include-linked-api-subdomains
```

Choose limits to match your test window:

| Option | Purpose |
| --- | --- |
| `--request-budget 5000` | Hard total request limit, including discovery, retries and redirects |
| `--requests-per-target 200` | Derive the module budget from distinct discovered URL/method combinations |
| `--crawler-budget 1000` | Limit discovery requests separately |
| `--time-budget 30m` | Limit overall scan duration |
| `--rate-limit 5` | Limit request rate |
| `--concurrency 4` | Limit concurrent workers |

For bounded module scans, AKCA divides the remaining budget across enabled modules
and reserves shares for URLs and their parameters. Query-value variants and extra
parameters share a URL's allocation. Unused shares move forward to later work.
A positive `--request-budget` takes precedence over `--requests-per-target`.

The default module scan has no request quota. Set both request options to `0` to
keep that behavior; scope, discovery limits, profiles and time limits still apply.

Budget-interrupted targets are reported as **incomplete**. They are not automatically
resumed when a later module returns unused budget. Unlimited requests do not
guarantee complete discovery or detection of every vulnerability.

## Reports and evidence

```bash
akca -u https://staging.example.com -f html -o report.html
akca -u https://staging.example.com -f json -o report.json
akca -u https://staging.example.com -f sarif -o results.sarif -q

# Replay a finding from the local evidence store
akca replay --finding 42
```

Each scan command above starts a separate scan. Supported output formats are
`html`, `json`, `markdown`, `csv` and `sarif`.

HTML reports include expandable HTTP evidence and copy buttons. Recorded matching
values can be highlighted in yellow inside responses. Passive secret findings
preserve a bounded excerpt around the match. Missing headers, timing differences
and external callbacks may have no response text to highlight; inspect their
verification context instead.

Depending on the finding, reports include payloads, confidence, proof-policy status,
typed observations, cURL reproduction, CWE and OWASP mappings. Internal reports
can also separate unproven leads for manual review.

**Treat evidence as sensitive.** Reports may contain raw credentials, cookies,
tokens and response data. The current report export does not automatically mask
these values. Review files before sharing them.

## How verification works

```text
Target / API definition
          |
          v
Preflight and fingerprinting
          |
          v
HTTP + browser + JavaScript + API discovery
          |
          v
Parameter analysis and module scheduling
          |
          v
Probe -> module-specific controls -> verification
          |
          v
SQLite evidence -> report policy -> exported findings
```

Verification may use replay, negative controls, timing comparisons, identity/state
observations, browser execution or correlated OAST callbacks. Passive content and
configuration checks use their own evidence paths. A `Confirmed` label should be
read together with its stored proof and the module's limitations.

See the [verification audit](engine/docs/FALSE_POSITIVE_AUDIT.md) for additional context.

## API definition support

| Input | Use |
| --- | --- |
| OpenAPI / Swagger | Operations, parameters and request schemas, including OpenAPI 3.0/3.1 bodies |
| RAML | Resources, methods and bundled includes |
| Postman | Collections and environment-variable expansion |
| HAR | Captured requests and parameters |
| GraphQL | Typed variables and selection templates |
| WSDL | SOAP service and operation discovery |
| protobuf | gRPC service and RPC discovery |
| AsyncAPI | Channel inventory |

Imported definitions feed the endpoint inventory. Discovery support for a format
does not imply that every operation or protocol receives every vulnerability check.
ZIP imports enforce path and size limits when resolving bundled files.

## Build and contribute

```bash
git clone https://github.com/akha-security/akca.git
cd akca/engine
go build -buildvcs=false -trimpath -o ../akca ./cmd/akca
../akca --version
```

For Windows PowerShell, use:

```powershell
git clone https://github.com/akha-security/akca.git
Set-Location akca\engine
go build -buildvcs=false -trimpath -o ..\akca.exe .\cmd\akca
..\akca.exe --version
```

From `engine/`, validate changes with:

```bash
go test ./... -count=1
go vet ./...
go run ./cmd/akca benchmark --strict
```

The benchmark evaluates its observed corpus; it does not establish universal
detection coverage. AKCA is an early `v0.2.0` release under active development.

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Reproducible bug reports, regression fixtures
and focused improvements are welcome. Report vulnerabilities in AKCA itself
through [SECURITY.md](SECURITY.md).

## License

Copyright 2026 AKHA Security contributors.
Licensed under the [Apache License 2.0](LICENSE).
