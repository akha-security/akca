# Akca - Demo Version

[![Status: Demo](https://img.shields.io/badge/status-demo%20%2F%20experimental-f59e0b)](https://github.com/akha-security/akca)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Quality](https://github.com/akha-security/akca/actions/workflows/quality.yml/badge.svg)](https://github.com/akha-security/akca/actions/workflows/quality.yml)

**Akca is an experimental, proof-oriented DAST and bug bounty scanner written in Go.**

It combines crawling, active and passive checks, browser-assisted analysis, out-of-band verification, API discovery, and evidence-aware reporting in one CLI workflow.

> [!IMPORTANT]
> **Akca is currently a demo release.**
>
> The main version is still under active development. This repository may contain bugs, incomplete checks, unstable behavior, breaking changes, false positives, and false negatives. Do not treat a clean Akca report as proof that a target is secure, and manually verify every finding before submitting a bug bounty report or making a security decision.

## Why this repository is public

Akca is being released early so that real-world feedback can shape the main version. Testing, reproducible bug reports, false-positive samples, missed-vulnerability reports, and feature suggestions are especially valuable.

Please open an issue if you encounter:

- an installation, startup, scan, browser, OAST, database, or reporting error;
- a finding that cannot be reproduced manually;
- a vulnerability that Akca failed to detect;
- a module, payload family, workflow, or report section that needs improvement;
- a protocol, vulnerability class, integration, or feature that should be added.

Use the [GitHub issue tracker](https://github.com/akha-security/akca/issues/new) and prefix the title with `[Bug]`, `[False Positive]`, `[False Negative]`, or `[Feature]`.

## Responsible use

Only scan systems that you own or are explicitly authorized to test. You are responsible for respecting the target's scope, rate limits, data-handling rules, and applicable laws.

Active security testing can modify application state, trigger alerts, create records, consume resources, or interact with third-party infrastructure. Start with a test environment whenever possible.

## Installation

### Requirements

- Go 1.25 or newer
- Internet access during installation
- Internet access on the first browser-assisted scan when no compatible local browser exists

### Install with one command

```bash
go install -v github.com/akha-security/akca/engine/cmd/akca@latest
```

This is the standard installation method. It does not require cloning the
repository, running `go build`, or manually downloading Go dependencies.
The Go toolchain resolves, downloads, builds, and installs Akca and its Go
dependencies in a single command.

Verify the installation:

```bash
akca --version
```

If the command is not found, add Go's binary directory to your `PATH`:

**Linux and macOS**

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

**Windows PowerShell**

```powershell
$env:Path += ";$(go env GOPATH)\bin"
```

> [!NOTE]
> `@latest` installs the newest published Akca engine version. Demo releases
> may introduce breaking changes until the first stable release.

## Automatic browser setup

Akca does not require a separate ChromeDriver or Playwright installation.

At scan startup it:

1. uses an available Chrome, Chromium, or Microsoft Edge installation;
2. checks the local managed-browser cache;
3. downloads a compatible portable Chromium build automatically when no browser is available.

The downloaded browser is cached and reused by later scans. Browser preparation happens only when a scan needs to start; commands such as `akca --help` and `akca --version` do not trigger a download.

If browser provisioning fails, Akca continues with HTTP-based coverage and clearly warns that DOM execution and browser-assisted checks may be incomplete.

On minimal Linux distributions, Chromium may still require operating-system shared libraries supplied by the distribution. Akca cannot safely install system packages without administrator approval.

## Quick start

Run an authorized scan and generate an HTML report:

```bash
akca -u https://target.example -o akca-report.html
```

Use authentication headers:

```bash
akca -u https://target.example \
  -H "Authorization: Bearer REDACTED" \
  -H "X-API-Key: REDACTED" \
  -o authenticated-scan.html
```

Use a session cookie:

```bash
akca -u https://target.example \
  -c "session=REDACTED" \
  -o authenticated-scan.html
```

Send traffic through an intercepting proxy:

```bash
akca -u https://target.example \
  -p http://127.0.0.1:8080 \
  -k \
  -o proxied-scan.html
```

Seed the scan from an OpenAPI document:

```bash
akca -u https://api.target.example \
  --api-spec ./openapi.json \
  -o api-scan.html
```

Tune request pressure:

```bash
akca -u https://target.example \
  --rate-limit 20 \
  --concurrency 5 \
  -o controlled-scan.html
```

## What Akca currently covers

Akca's demo build includes multiple discovery and verification paths. Module maturity varies, so this list describes intended coverage rather than a guarantee of detection.

### Discovery and attack-surface mapping

- HTML links, forms, parameters, scripts, and redirects
- JavaScript and source-map assisted endpoint discovery
- OpenAPI/API route seeding
- parameterless and API-style endpoints
- technology and passive response analysis
- browser-assisted DOM and reflection analysis
- selected request-header injection points, including `User-Agent`, `Referer`, `Origin`, and forwarding headers

### Active vulnerability checks

- SQL injection, including error, boolean, time, and out-of-band evidence paths
- NoSQL injection, including operator-style and backend-specific probes
- reflected, stored-signal, DOM, and blind XSS paths
- server-side template injection
- command injection
- server-side request forgery
- XML external entity injection
- path traversal and file-oriented checks
- open redirect
- selected authentication, authorization, CORS, header, exposure, and misconfiguration checks

### Verification and evidence

- baseline-versus-probe comparison
- positive and negative controls where supported
- repeated timing samples for timing-sensitive checks
- browser execution evidence for relevant client-side checks
- OAST correlation for blind or asynchronous behavior
- proof-aware confidence classification
- request, response, payload, parameter, and reproduction context in reports

## Confidence levels

Akca separates signal strength from severity:

| Confidence | Meaning |
|---|---|
| `Confirmed` | The configured proof contract was satisfied. Manual verification is still required. |
| `HighConfidence` | Strong, reproducible evidence exists, but the strict confirmation contract was not fully satisfied. |
| `Potential` | A meaningful signal exists and requires deeper manual investigation. |
| `NeedsManualReview` | The signal is ambiguous, passive, environmental, or not safely verifiable automatically. |

A high-severity label does not automatically mean a finding is confirmed. Likewise, a low-confidence result is not necessarily harmless.

## Reports

HTML is the recommended format for manual review:

```bash
akca -u https://target.example -f html -o report.html
```

Supported formats:

- `html`
- `json`
- `csv`
- `markdown`
- `sarif`

The final report is designed to preserve active, passive, confirmed, high-confidence, potential, and manual-review findings. Integration and policy outputs may apply stricter proof gates than the full evidence report.

Never publish an unredacted report from a private program. Reports may contain target URLs, parameters, payloads, response fragments, tokens, cookies, internal hostnames, or personal data.

## Common CLI options

| Option | Description |
|---|---|
| `-u`, `--url` | Target URL |
| `-c`, `--cookie` | Cookie header |
| `-H`, `--header` | Custom header; may be repeated |
| `-p`, `--proxy` | HTTP proxy |
| `-k`, `--insecure` | Allow invalid TLS certificates |
| `--rate-limit` | Maximum request rate |
| `--concurrency` | Concurrent worker count |
| `--api-spec` | OpenAPI/API specification path |
| `--oast-server` | Custom OAST service |
| `--oast-wait` | OAST callback wait duration |
| `--no-oast` | Disable OAST checks |
| `--no-fuzzing` | Disable active fuzzing |
| `--no-js` | Disable JavaScript-assisted analysis |
| `-f`, `--format` | Report format |
| `-o`, `--output` | Report output path |
| `--scan-id` | Explicit scan identifier |
| `--version` | Print version information |

Run `akca --help` for the current command reference.

## OAST and external traffic

Some SSRF, blind XSS, XXE, command injection, and similar checks may use out-of-band interaction. Review the configured OAST provider and your program's rules before enabling these checks.

Disable OAST when external callbacks are not permitted:

```bash
akca -u https://target.example --no-oast -o report.html
```

OAST transport errors do not prove that a target is vulnerable or safe. They should be treated as coverage warnings.

## Demo limitations

The current demo can produce incomplete or incorrect results. Known risk areas include:

- highly dynamic SPAs and applications with complex browser state;
- multi-step authentication, MFA, CAPTCHA, and rotating anti-CSRF controls;
- rate limiting, WAF normalization, caching, load balancing, and unstable responses;
- blind and time-based vulnerabilities affected by network noise;
- destructive business workflows that cannot be tested safely by default;
- custom serialization, GraphQL, WebSocket, gRPC, and proprietary protocols;
- OAST providers blocked by DNS, proxies, egress policy, or target infrastructure;
- browser startup and rendering differences across operating systems;
- uncommon database, template-engine, and framework fingerprints;
- authorization issues requiring multiple users, roles, tenants, or account states;
- vulnerabilities whose proof requires human context or a program-specific impact chain.

Akca is an aid for security testing, not a replacement for manual methodology, source review, threat modeling, or professional judgment.

## Reporting useful feedback

Before opening an issue, remove credentials, cookies, authorization tokens, private hostnames, personal data, and bug bounty program secrets.

A useful issue should include:

```text
Title: [Bug | False Positive | False Negative | Feature] Short summary

Akca version:
Operating system:
Go version:
Installation method:
Target type/framework (if known):
Command used (secrets redacted):

Expected behavior:
Actual behavior:

Minimal reproduction:
1.
2.
3.

Relevant redacted request/response:
Relevant report excerpt:
Logs or error message:
```

For a false positive, explain how you manually tested the finding and why the behavior is not exploitable.

For a missed vulnerability, provide the smallest safe lab reproduction, vulnerability class, injection location, expected payload behavior, and the evidence Akca should have recognized.

For a requested improvement, describe the security-testing workflow it would unlock rather than only naming a tool or payload.

## Build from source

```bash
git clone https://github.com/akha-security/akca.git
cd akca/engine
go test ./...
go build ./cmd/akca
```

Run the local build:

```bash
./akca -u https://target.example -o report.html
```

On Windows:

```powershell
.\akca.exe -u https://target.example -o report.html
```

## Development checks

From the `engine` directory:

```bash
go test ./...
go vet ./...
go build ./cmd/akca ./cmd/akca-api ./cmd/akca-policy
```

Contributions should include focused tests and should not weaken proof requirements merely to increase finding counts.

## Roadmap

The main version is still being developed. Current priorities include:

- broader vulnerability-class parity;
- stronger false-positive controls and negative-control coverage;
- more reliable browser and JavaScript analysis;
- authenticated and multi-role workflow testing;
- richer API, GraphQL, WebSocket, and modern application coverage;
- safer state-changing request policies;
- better scan recovery, observability, and large-target performance;
- reproducible test labs and transparent quality gates;
- improved evidence, remediation guidance, and integrations.

Roadmap priorities may change based on reproducible community feedback.

## Project status

Akca is **demo software**, not a stable production release. Interfaces, flags, storage formats, browser behavior, modules, payloads, and report schemas may change without backward compatibility until the first stable release.

- Repository: [github.com/akha-security/akca](https://github.com/akha-security/akca)
- Issues and feedback: [github.com/akha-security/akca/issues](https://github.com/akha-security/akca/issues)
- Maintainer: [@akha-security](https://github.com/akha-security)

If Akca reports something wrong, misses something important, fails in your environment, or lacks a capability you need, please report it. Reproducible feedback is one of the most valuable contributions you can make to the project.
