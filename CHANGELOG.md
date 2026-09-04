# Changelog

All notable changes to AKCA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- GitHub community, contribution and security documentation.
- `go install -v github.com/akha-security/akca/engine/cmd/akca@latest`
  installation instructions.
- `--include-linked-api-subdomains` to opt into the previous broad crawler scope
  expansion for linked API/service subdomains.

### Fixed

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
