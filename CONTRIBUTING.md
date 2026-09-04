# Contributing to AKCA

Thank you for helping improve AKCA Advanced Web Security Scanner.

## Before you start

- Use AKCA only against systems you are authorized to test.
- Open an issue before a large architectural change.
- Keep pull requests focused and explain the security model being changed.
- Never commit credentials, real customer traffic, private target data, or
  weaponized examples that are unnecessary to test the behavior.

Security vulnerabilities in AKCA itself must be reported through
[SECURITY.md](SECURITY.md), not a public issue.

## Development setup

```bash
git clone https://github.com/akha-security/akca.git
cd akca/engine
go mod download
go test ./... -count=1
go vet ./...
go build -buildvcs=false ./cmd/akca
```

Go `1.25` or newer is required.

## Pull-request checklist

- Run `gofmt` on changed Go files.
- Add positive and safe-negative tests for detection changes.
- Add an unstable/error-path test when response comparison is involved.
- Preserve scope, request-budget and cancellation behavior.
- Do not make a WAF or optimization path silently disable scan capabilities.
- Keep candidate detection separate from proof-policy publication.
- For state-changing checks, provide state verification and cleanup behavior.
- Confirm secrets and authorization material are redacted from storage/reports.
- Run `go test ./... -count=1` and `go vet ./...`.
- Update README, FEATURES, architecture notes, or CLI help when behavior changes.

## Adding or changing a security module

A complete module change normally touches:

1. The module manifest and precondition
2. The module dispatcher and execution order
3. Its vulnerability-specific proof policy
4. Positive, negative-control and replay tests
5. Passive-mode behavior where applicable
6. Finding text, severity, CWE/OWASP classification and remediation

An HTTP `2xx`, reflection, timing delay, or response difference is not sufficient
proof by itself. Explain why the evidence demonstrates a security boundary or
impact and how the negative case is ruled out.

## Commit and review guidance

Write imperative commit subjects such as `Add RAML external reference support`.
In the pull request, include:

- What changed
- Why it is needed
- How false positives are controlled
- How it was tested
- Whether it changes network traffic or application state

By contributing, you agree that your contribution is licensed under the
repository's Apache License 2.0.
