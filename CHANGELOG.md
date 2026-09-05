# Changelog

All notable changes to AKCA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

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

[Unreleased]: https://github.com/akha-security/akca/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/akha-security/akca/releases/tag/v0.1.0
