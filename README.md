<h1 align="center">AKCA</h1>
<p align="center"><strong>Advanced Web Security Scanner</strong></p>
<p align="center">Discover endpoints. Test web applications. Inspect the evidence.</p>

<p align="center">
  <a href="https://github.com/akha-security/akca/actions/workflows/ci.yml"><img src="https://github.com/akha-security/akca/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/akha-security/akca/releases/tag/v0.2.0"><img src="https://img.shields.io/badge/version-v0.2.0-8b5cf6" alt="Version v0.2.0"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white" alt="Go 1.25 or newer"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache License 2.0"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#scan-profiles">Profiles</a> ·
  <a href="#reports">Reports</a> ·
  <a href="FEATURES.md">Features</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

AKCA is an open-source web security scanner written in Go. It combines HTTP crawling, browser-assisted discovery, JavaScript analysis, and API imports with active and passive security checks. Findings include recorded evidence to help you investigate and reproduce the result.

## Installation

### Go install

Requires **Go 1.25 or newer**.

```bash
go install github.com/akha-security/akca/engine/cmd/akca@latest
akca --version
```

<details>
<summary>Command not found? Configure your PATH.</summary>

For the default Go installation, add the Go binary directory to your current terminal's `PATH`.

**Linux / macOS**

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

Add that line to your shell configuration to keep it across sessions.

**Windows PowerShell**

```powershell
$env:Path += ";$(go env GOPATH)\bin"
```

For future sessions, add the same directory to your user `Path` environment variable. If you configured `GOBIN`, use that directory instead.

</details>

### Prebuilt binaries

Download your build from [GitHub Releases](https://github.com/akha-security/akca/releases/latest). Releases include `SHA256SUMS.txt` for checksum verification.

| Platform | Architecture | Asset |
| --- | --- | --- |
| Linux | x64 / ARM64 | `akca-linux-amd64` / `akca-linux-arm64` |
| macOS | Intel / Apple Silicon | `akca-darwin-amd64` / `akca-darwin-arm64` |
| Windows | x64 | `akca-windows-amd64.exe` |

On Linux or macOS, make the downloaded file executable. For Linux x64:

```bash
chmod +x akca-linux-amd64
./akca-linux-amd64 --help
```

On Windows, rename the download to `akca.exe` and run `.\akca.exe --help` in PowerShell. The examples below assume `akca` is available on your `PATH`.

Browser-backed checks require Chrome, Chromium, or Edge.

## Usage

Use AKCA only on systems you own or have permission to test. Replace the example URL with your authorized target.

### Start a scan

```bash
akca -u https://example.com
```

The default profile is `full`. To save an HTML report:

```bash
akca -u https://example.com -f html -o report.html
```

### Choose specific checks

Run SQL injection, XSS, and server-side injection checks, including SSTI:

```bash
akca -u https://example.com -m sql,xss,rce
```

Run passive checks:

```bash
akca -u https://example.com -m passive
```

Passive scans still send requests for discovery and inspection.

### Use an authenticated session

Supply a session cookie:

```bash
akca -u https://example.com -c "session=YOUR_SESSION_COOKIE"
```

Or an authorization header:

```bash
akca -u https://example.com -H "Authorization: Bearer YOUR_TOKEN"
```

Some authorization checks require additional identities or state configuration beyond a single session.

### Import an API definition

```bash
akca -u https://api.example.com --api-spec ./openapi.yaml -m api
```

Discovery supports OpenAPI/Swagger, RAML, Postman, HAR, GraphQL, WSDL, protobuf, and AsyncAPI inputs, including supported ZIP bundles. Testing coverage depends on the imported protocol and operation.

### Inspect traffic through a proxy

```bash
akca -u https://example.com -p http://127.0.0.1:8080
```

Run `akca --help` for all available options.

## Scan profiles

Select a profile with `-m`, or combine several with commas.

| Profile | Checks |
| --- | --- |
| `full` | All enabled active and passive modules; the default |
| `sql` | SQL and NoSQL injection |
| `xss` | Reflected, stored, DOM, and blind XSS; related client-side checks |
| `rce` | Command injection, SSTI, deserialization, and related checks |
| `api` | API exposure, BOLA/IDOR, BFLA, mass assignment, and token checks |
| `graphql` | GraphQL schema and operation checks |
| `ssrf` | SSRF, XXE, and related out-of-band checks |
| `auth` | Authentication, authorization, CSRF, and cookie/header checks |
| `passive` | Metadata, TLS, security headers, secrets, and component analysis |
| `fuzz` | Paths, exposed artifacts, traversal, and related checks |

Execution depends on discovered endpoints, configuration, available verification capabilities, and scan limits. See [FEATURES.md](FEATURES.md) for the full capability guide.

## Scope and scan limits

Set a total request budget and maximum duration:

```bash
akca -u https://example.com --request-budget 5000 --time-budget 30m
```

Or calculate the module budget from discovered URL/method combinations:

```bash
akca -u https://example.com --requests-per-target 200
```

AKCA distributes bounded module budgets across modules, URLs, and parameters. Unused allocations move forward to later work. A positive `--request-budget` takes precedence over `--requests-per-target`.

| Option | Purpose |
| --- | --- |
| `--request-budget 5000` | Cap total requests, including discovery, retries, and redirects |
| `--requests-per-target 200` | Derive the module budget from discovered URL/method combinations |
| `--crawler-budget 1000` | Limit discovery requests |
| `--time-budget 30m` | Limit scan duration |
| `--rate-limit 5` | Limit requests per second |
| `--concurrency 4` | Limit concurrent workers |

By default, the module scan has no request quota. Budget interruptions are reported as **incomplete coverage**. Interrupted targets are not automatically resumed when later work returns unused budget. No budget setting guarantees detection of every vulnerability.

Linked API/service subdomains are outside the default target scope. To include linked subdomains under the same root:

```bash
akca -u https://www.example.com --include-linked-api-subdomains
```

## Reports

Choose an output format with `-f` and a file path with `-o`:

```bash
akca -u https://example.com -f html -o report.html
```

Supported formats: **HTML, JSON, Markdown, CSV, and SARIF**. Each invocation starts a new scan.

HTML reports provide expandable HTTP evidence and copy controls. Where a finding preserves a matching response value, AKCA highlights it in **yellow**, helping you locate a reflected payload or exposed secret. Passive secret findings retain an excerpt around the match.

Depending on the module, findings include:

- Recorded HTTP requests and responses.
- Payloads and cURL reproduction commands.
- Confidence, verification observations, and proof-policy status.
- CWE and OWASP mappings.

Timing findings, missing headers, and external callbacks may have no response text to highlight. Their verification context supplies the relevant evidence.

Replay a stored finding:

```bash
akca replay --finding 42
```

Reports can contain raw credentials, cookies, tokens, and response data. Export does not automatically mask these values; review evidence before sharing it.

## What's new in v0.2.0

- Adaptive URL-based module budgets with unused-budget rollover and incomplete-coverage notices.
- Broader SQL probes and preservation of POST parameters in fallback targets.
- Expanded response highlighting and evidence excerpts for supported passive findings.

See [CHANGELOG.md](CHANGELOG.md) for release details.

## Development

Build from source:

```bash
git clone https://github.com/akha-security/akca.git
cd akca/engine
go build -buildvcs=false -trimpath -o ../akca ./cmd/akca
```

On Windows, use `-o ../akca.exe` for the executable name.

Run checks from the `engine` directory:

```bash
go test ./... -count=1
go vet ./...
go run ./cmd/akca benchmark --strict
```

The benchmark measures its observed corpus. For implementation details and verification limitations, read the [architecture guide](engine/docs/ARCHITECTURE.md) and [verification audit](engine/docs/FALSE_POSITIVE_AUDIT.md).

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request. Report vulnerabilities in AKCA through [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE) · Copyright 2026 AKHA Security contributors.
